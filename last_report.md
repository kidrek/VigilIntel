# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Scan depuis le sous-réseau 109.160.32.0/24, (lun. 23 nov.)](#scan-depuis-le-sous-reseau-10916032024-lun-23-nov)
  * [LATAM’s Financial Fraud Ecosystem: Key Threats and Strategies for Business Protection](#latams-financial-fraud-ecosystem-key-threats-and-strategies-for-business-protection)
  * [Faille Microsoft Azure exploitée pour voler les identifiants API des clients](#faille-microsoft-azure-exploitee-pour-voler-les-identifiants-api-des-clients)
  * [sunspotsvoices.com par inc ransom](#sunspotsvoicescom-par-inc-ransom)
  * [Possible Phishing 🎣  on: ⚠️hxxps[:]//tienda[.]airis[.]es/js/de  🧬 Analysis at: https://urldna.io/scan/6b05bc4d3b775000076a72d6 #cybersecurity #phishing #infosec #urldna #scam #infosec](#possible-phishing-on-hxxpstiendaairisesjsde-analysis-at-httpsurldnaioscan6b05bc4d3b775000076a72d6-cybersecurity-phishing-infosec-urldna-scam-infosec)
  * [OpenAI et Cisco dévoilent Shirudo pour bloquer les exploits avant les correctifs](#openai-et-cisco-devoilent-shirudo-pour-bloquer-les-exploits-avant-les-correctifs)
  * [Copperstone Clothing Company (fabricant/exportateur indien de vêtements, parc ERP SQL Server) par pixelleaks](#copperstone-clothing-company-fabricantexportateur-indien-de-vetements-parc-erp-sql-server-par-pixelleaks)
  * [Webworm, un APT d'espionnage aligné sur la Chine, a reconstruit SoftEther VPN à partir du code source et l'utilise comme backdoor personnalisée](#webworm-un-apt-despionnage-aligne-sur-la-chine-a-reconstruit-softether-vpn-a-partir-du-code-source-et-lutilise-comme-backdoor-personnalisee)
  * [FastUnlock : une vulnérabilité zero-day non corrigée de Windows 11 transforme Narrator en un moyen de passer outre l'écran de verrouillage](#fastunlock-une-vulnerabilite-zero-day-non-corrigee-de-windows-11-transforme-narrator-en-un-moyen-de-passer-outre-lecran-de-verrouillage)
  * [Impossible de cross-poster une vidéo Twitter vers Telegram, mais la CIA enquête aujourd'hui sur une compromission.](#impossible-de-cross-poster-une-video-twitter-vers-telegram-mais-la-cia-enquete-aujourdhui-sur-une-compromission)
  * [États-Unis : Le FBI visé par un nouveau piratage, ses bases de données criminelles en question](#etats-unis-le-fbi-vise-par-un-nouveau-piratage-ses-bases-de-donnees-criminelles-en-question)
  * [L'IA détecte désormais des failles « zero-day » pour seulement 4$](#lia-detecte-desormais-des-failles-zero-day-pour-seulement-4)
  * [Noël : ces mots de passe qui fragilisent la sécurité des entreprises](#noel-ces-mots-de-passe-qui-fragilisent-la-securite-des-entreprises)
  * [Les passerelles série industrielles diffusent qu'elles sont non sécurisées](#les-passerelles-serie-industrielles-diffusent-quelles-sont-non-securisees)
  * [OXLoader exploite le détournement de DLL pour distribuer différentes familles de logiciels malveillants](#oxloader-exploite-le-detournement-de-dll-pour-distribuer-differentes-familles-de-logiciels-malveillants)
  * [sunnybrook.ca par scarlettgroup](#sunnybrookca-par-scarlettgroup)
  * [Peninsula Energy suspend la cotation après qu'un incident cyber a touché une mine d'uranium américaine](#peninsula-energy-suspend-la-cotation-apres-quun-incident-cyber-a-touche-une-mine-duranium-americaine)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La journée est dominée par 67 vulnérabilités, soit le volume le plus élevé, ce qui impose une priorisation rapide des correctifs exposés et une vérification de l’exploitabilité réelle plutôt qu’un simple décompte. Les 29 violations de données confirment une pression persistante sur les données sensibles et justifient un renforcement de la détection des exfiltrations et de la surveillance des accès tiers. Les 8 items géopolitiques et 8 items réglementaires, bien que moins nombreux, structurent le risque contextuel et peuvent accélérer les décisions de conformité ou de durcissement. Les 5 acteurs de menace identifiés restent un signal ciblé à corréler avec les vulnérabilités et les fuites observées pour distinguer les campagnes actives des simples mentions. Les 17 articles complètent ce panorama en apportant du contexte exploitable pour la veille et la priorisation. La priorité opérationnelle est donc de traiter les vulnérabilités critiques exploitables, de qualifier les fuites à impact élevé et de suivre l’évolution géopolitique et réglementaire comme facteurs d’accélération du risque.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **ShinyHunters** | secteur public, énergie, vérification d'identité | Compromission d'environnements exposés, vol de données et extorsion via site de fuite. | T1190, T1078, T1213, T1567, T1657 | [https://theperimetersite.com/report/521](https://theperimetersite.com/report/521)<br>[https://infosec.exchange/@theperimetersite/117673585526604967](https://infosec.exchange/@theperimetersite/117673585526604967) |
| **n0n** | adtech | Revendication ransomware avec fuite de données, non vérifiée. | T1486, T1657, T1567 | [https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Matchbook3469/117672886204149587](https://mastodon.social/@Matchbook3469/117672886204149587)<br>[https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/](https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/) |
| **PixelLeaks** |  | Double extorsion, exfiltration de données et ciblage d'ERP/SQL Server exposés. | T1486, T1657, T1567 | [https://www.ransomlook.io//group/pixelleaks](https://www.ransomlook.io//group/pixelleaks) |
| **Webworm** |  | Tunnélisation VPN SoftEther personnalisée, masquage, infrastructure de C2 et exploitation de services exposés pour de l'espionnage. | T1572, T1036, T1027, T1090, T1190, T1595 | [https://www.darkreading.com/perimeter/webworm-slithers-customized-softether-vpn](https://www.darkreading.com/perimeter/webworm-slithers-customized-softether-vpn) |
| **Scarlettgroup** | santé | Double extorsion avec exfiltration et publication de données sur site onion. | T1657, T1486, T1567 | [https://www.ransomlook.io//group/scarlettgroup](https://www.ransomlook.io//group/scarlettgroup) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Iran, Chypre, Arabie saoudite, Moyen-Orient, Golfe** | Télécommunications, transport aérien, santé, infrastructures critiques, gouvernement | Espionnage cyber iranien : nouveau cluster Volant Manticore, backdoor KuboShell à commande via IPFS et usage détourné d'outils RMM légitimes | Check Point Research documente Volant Manticore, groupe d’espionnage aligné sur l’Iran et évalué comme affilié au ministère du Renseignement et de la Sécurité (MOIS), actif depuis fin août 2025 avec une chronologie remontant à septembre 2025. Il est présenté comme le premier groupe iranien identifié à faire de Chypre une cible primaire d’espionnage, visant les opérateurs télécoms, les compagnies aériennes et les infrastructures critiques ; l’attribution repose sur le partage d’outillage et de tradecraft avec MuddyWater, dont Volant Manticore serait une scission opérée par d’anciens opérateurs, désormais cluster autonome avec des TTP distinctes et un périmètre régional resserré, réutilisant un framework plus ancien et le playbook de MuddyWater tout en divergeant vers ses propres méthodes, notamment des campagnes de collecte d’identifiants. La chaîne d’attaque observée depuis juillet 2026 repose sur des personas générées par IA dans de faux CV, dont « Athena Marinou », profil de tourisme basé à Chypre, redirigeant vers un site d’emploi légitime et incitant la cible à télécharger un lien, puis sur KuboShell, backdoor Windows utilisant l’IPFS et le service Pinata pour le command-and-control et le transfert de fichiers en pair-à-pair, un choix qui complique le blocage par réputation d’infrastructure ; KuboShell vérifie ses privilèges au démarrage, tente une élévation via une invite UAC, récupère l’adresse MAC de la première carte réseau comme identifiant unique de victime et enregistre l’hôte via un fichier journal dans C:\Users\Public. Il déploie ensuite Homa, framework post-compromission bâti sur une réimplémentation du client MuddyC2Go de MuddyWater, et le groupe complète son arsenal par des outils RMM légitimes détournés (MeshCentral, NetLock RMM, N-able RMM) pour la persistance. L’analyse de l’environnement opérateur montre des phases de développement, de test et d’exploitation, on-premise comme dans le cloud, avec des tests de leurs outils contre les antivirus avant déploiement et l’usage de clients Fortinet SSL VPN, ce qui suggère un accès aux réseaux victimes via VPN. Le ciblage suit l’actualité géopolitique : une compagnie aérienne opérant entre Chypre et Israël, puis, en septembre 2026, en phase avec l’escalade entre l’Arabie saoudite et les Houthis soutenus par l’Iran, une réorientation brutale vers Riyad et des entités de santé saoudiennes, cohérente avec l’historique du MOIS contre les hôpitaux en période de conflit, avec des campagnes de phishing via des archives ZIP à thème santé (« AI_Healthcare_Seminar.zip », « Ai_Healthcare_Seminar_Online.zip ») envoyées parfois depuis un compte compromis d’un hôpital privé saoudien. Chypre, du fait de ses liens défensifs et énergétiques croissants avec Israël et la Grèce et de son rôle de hub pour les opérations militaires occidentales, constitue une cible naturelle pour la collecte iranienne ; le pays figure parmi ceux où le ciblage de caméras IP par des acteurs liés à l’Iran a augmenté à partir du 28 février 2026, activité pouvant précéder des frappes et soutenir l’évaluation des dommages post-combat. La priorisation des cibles apparaît donc directement pilotée par la conjoncture géopolitique, ce qui en fait un indicateur avancé de tension régionale. | [https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/](https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/)<br>[https://thehackernews.com/2026/11/iran-aligned-volant-manticore-uses-ipfs.html](https://thehackernews.com/2026/11/iran-aligned-volant-manticore-uses-ipfs.html)<br>[https://infosec.exchange/@edwardk/117673148163107645](https://infosec.exchange/@edwardk/117673148163107645) |
| **Mondial, États-Unis, Chine, Russie, Europe, Orbite terrestre et lunaire** | Spatial commercial et institutionnel, télécommunications par satellite, défense | Cybersécurité de l'écosystème spatial dans la « course à l'espace 2.0 » : segment sol, terminaux, chaîne d'approvisionnement et militarisation orbitale | Recorded Future (Insikt Group) replace la cybersécurité au cœur de la seconde course à l'espace. Le contexte est celui d'une croissance explosive : 329 tentatives de lancement orbital en 2025 (contre 263 l'année précédente), un record de 4 517 satellites mis en orbite dont 87 % commerciaux, une économie spatiale à 686 milliards de dollars, le survol lunaire habité d'Artemis II en avril 2026, la réorientation de la NASA vers une base lunaire au détriment de Gateway en mars, et l'objectif chinois d'un taïkonaute sur la Lune d'ici 2030 puis d'une station internationale de recherche lunaire en 2035. Or chaque satellite, lander, rover ou relais est un ordinateur exécutant du logiciel, relié à une station sol elle-même connectée à Internet : la surface d'attaque croît donc exponentiellement. Le cas fondateur reste l'attaque du 24 février 2022 contre KA-SAT/Viasat, une heure avant l'entrée des blindés russes en Ukraine : le malware essuie-données AcidRain, diffusé via le réseau de gestion de l'opérateur, a éteint des dizaines de milliers de modems en Europe, privé l'armée ukrainienne de son C2, coupé la télésurveillance d'environ 5 800 éoliennes en Allemagne et l'accès Internet d'abonnés de Pologne à la France — attribuée depuis par le Royaume-Uni, les États-Unis et l'UE à la Russie. L'enseignement clé est que l'espace n'est pas un sanctuaire : « chaque opération spatiale a une adresse postale » — stations de commandement, liaisons de télémesure, terminaux utilisateurs et chaîne logicielle sont les véritables portes d'entrée, et elles sont souvent mal verrouillées. Des chercheurs de l'UC San Diego et du Maryland ont ainsi montré, avec une antenne à 800 dollars, qu'environ la moitié des satellites géostationnaires visibles émettaient en clair (backhaul télécom, trafic d'entreprise, communications militaires). En mars, la NSA et ses partenaires Five Eyes ont publié des recommandations conjointes alertant que la croissance des constellations en orbite basse élargit la surface d'attaque sur les segments spatiaux, sol et utilisateurs, ainsi que sur les chaînes d'approvisionnement. Enfin, la militarisation n'est plus implicite : le 14 septembre 2026, le secrétaire à l'Armée de l'air Troy Meink a confirmé pour la première fois que les États-Unis disposent d'armes de contrôle spatial en orbite à capacités offensives. Les acteurs étatiques, les hacktivistes (illustrés par l'aveuglement de la flotte pétrolière iranienne) et les groupes criminels convergent donc vers un secteur où l'interdépendance entre infrastructures civiles et militaires est totale. | [https://www.recordedfuture.com/blog/cyber-threats-space-race](https://www.recordedfuture.com/blog/cyber-threats-space-race) |
| **Asie-Pacifique, Asie de l'Est, Chine, Japon, Taïwan, Indo-Pacifique** | Diplomatie, défense, sécurité régionale | Détérioration des relations sino-japonaises révélée par le traitement protocolaire réservé à Tokyo au sommet de l'APEC 2026 à Shenzhen | L'analyse de l'IRIS (Marianne Peron-Doise) décrypte la froideur diplomatique observée au sommet de la Coopération économique pour l'Asie-Pacifique (APEC) de Shenzhen à l'égard de la Première ministre japonaise Sanae Takaichi, comme révélateur de l'une des périodes les plus tendues entre Pékin et Tokyo depuis plus d'une décennie. Les signaux protocolaires sont explicites : absence d'accueil cérémoniel comparable à celui réservé à d'autres dirigeants — à l'exception notable de Donald Trump et Vladimir Poutine, délibérément mis en avant — et surtout absence de tout entretien bilatéral avec Xi Jinping, alors que plusieurs chefs de gouvernement de la région, dont le président sud-coréen, ont bénéficié d'échanges directs. Le message est clair : l'amélioration de la relation avec Tokyo ne figure pas parmi les priorités immédiates du régime chinois. Cette tension s'articule sur deux socles. D'abord la mémoire : côté chinois, l'invasion japonaise de 1931-1945, inscrite dans le récit des « humiliations », est instrumentalisée pour dénoncer un « néo-militarisme » de Tokyo ; côté japonais, on estime que les excuses officielles répétées depuis les années 1970 et l'aide publique au développement (environ 3 660 milliards de yens, soit 23 milliards de dollars entre 1979 et 2022, ayant financé le métro de Pékin, l'aéroport de Shanghai-Pudong ou des installations portuaires) sont insuffisamment reconnues. Ensuite la géopolitique contemporaine : le principal point de friction reste les îles Senkaku/Diaoyu, administrées par le Japon mais revendiquées par la Chine, dont la nationalisation de trois îlots en 2012 a déclenché une multiplication des incursions de navires des garde-côtes chinois, désormais quasi quotidiennes selon Tokyo, tandis que les avions de la Force aérienne d'autodéfense réalisent plusieurs centaines d'interceptions par an. Cette pression aéromaritime s'inscrit dans la modernisation militaire chinoise, avec un budget de défense estimé à 336 milliards de dollars en 2025 contre 62 milliards pour le Japon (SIPRI). S'y ajoutent des désaccords croissants autour de Taïwan. Si l'interdépendance économique empêche encore une rupture totale, la logique de compétition stratégique semble désormais primer sur la logique de coopération, avec un risque d'entraînement régional et d'aggravation des incidents aéromaritimes. | [https://www.iris-france.org/le-japon-au-sommet-de-lapec-2026-une-froideur-diplomatique-qui-revele-lampleur-des-tensions-sino-japonaises/](https://www.iris-france.org/le-japon-au-sommet-de-lapec-2026-une-froideur-diplomatique-qui-revele-lampleur-des-tensions-sino-japonaises/) |
| **Amériques, États-Unis** | Politique intérieure américaine, gouvernance, relations internationales | Institutionnalisation du trumpisme et incertitudes de l'après-Trump au-delà de 2028 | L'analyse de l'IRIS (Véronique Chabourine) pose la question de la pérennité du trumpisme au-delà de la personne de Donald Trump. Tirant les enseignements de son premier mandat, ce dernier a entrepris depuis son retour à la Maison-Blanche de modifier les conditions d'exercice du pouvoir et de consolider ses relais institutionnels, politiques et économiques. La problématique centrale dépasse donc la seule succession de 2028 : elle réside dans la capacité du mouvement à inscrire durablement ses relais dans les structures politiques américaines, mais aussi dans les centres de décision et les leviers de puissance qui façonneront les rapports de force de demain. Autrement dit, le trumpisme pourrait survivre à Trump non pas comme une idéologie personnelle, mais comme un ensemble de dispositifs institutionnels, de réseaux d'influence et de positions de pouvoir capturés. Cette dynamique implique une recomposition des centres de puissance — administration, appareil judiciaire, agences, mais aussi sphère économique et médiatique — dont les effets se feront sentir bien après la fin du mandat. Pour les acteurs internationaux, l'incertitude porte sur la continuité ou la rupture des politiques étrangères, commerciales et sécuritaires selon que l'héritage sera ou non consolidé, ce qui impose de raisonner en scénarios plutôt qu'en pronostics. | [https://www.iris-france.org/le-trumpisme-survivra-t-il-a-trump-institutionnalisation-du-pouvoir-recomposition-des-centres-de-puissance-et-incertitudes-de-lapres-trump/](https://www.iris-france.org/le-trumpisme-survivra-t-il-a-trump-institutionnalisation-du-pouvoir-recomposition-des-centres-de-puissance-et-incertitudes-de-lapres-trump/) |
| **Chine, Asie-Pacifique, Mondial, Union européenne, États-Unis, Japon** | Mines et métaux critiques, aimants permanents, automobile, défense, électronique | Géoéconomie des terres rares : gestion d'un monopole comme actif stratégique et usage du contrôle à l'export comme levier de négociation | Le 9 novembre 2026, le MOFCOM et les douanes chinoises ont prolongé de deux mois, jusqu'au 10 janvier 2027, la suspension de six mesures de contrôle à l'export annoncées le 9 octobre 2025. Cette trêve est strictement calibrée : les contrôles d'avril 2025 restent en vigueur et soumettent à licence sept terres rares moyennes et lourdes, dont le dysprosium et le terbium, indispensables au maintien des propriétés magnétiques des aimants de moteurs électriques à haute température. La Chine assure 60 % de l'extraction mondiale destinée aux aimants, 91 % du raffinage, près de 95 % des aimants permanents et 97 % des capacités de séparation des terres rares lourdes (AIE, S&P Global). Cette position, construite depuis 1992 et protégée depuis décembre 2023 par l'interdiction d'exporter les techniques d'extraction, de séparation et de fabrication d'aimants, est désormais gérée comme un actif : maintenir une tension permanente mais contrôlée pour conserver la valeur politique du levier sans provoquer de rupture. Le calendrier des suspensions suit celui des négociations commerciales avec Washington, qui a aligné sa propre trêve sur le 10 janvier 2027, et la tension se convertit en rente (volumes exportés en baisse de 11,1 % sur les huit premiers mois de 2026, valeur en hausse de 53,5 % sur un an). Le précédent de 2010 est l'avertissement inverse : quotas réduits de 40 % et embargo de fait sur le Japon, suivis d'un investissement japonais massif (Sojitz, Jogmec, Lynas) ramenant la part chinoise des importations japonaises de plus de 90 % à 60-70 %, puis d'une condamnation de l'OMC en 2014. Un levier surexploité accélère la diversification de l'adversaire et déprécie l'actif. | [https://www.portail-ie.fr/univers/enjeux-de-puissances-et-geoeconomie/2026/terres-rares-la-chine-gere-son-monopole-comme-un-actif/](https://www.portail-ie.fr/univers/enjeux-de-puissances-et-geoeconomie/2026/terres-rares-la-chine-gere-son-monopole-comme-un-actif/) |
| **Chine, États-Unis, Asie-Pacifique, Europe, Taïwan** | Technologies critiques (IA, semi-conducteurs), infrastructures numériques, spatial, défense | Rivalité sino-américaine pour le leadership mondial : dimensions technologiques, normatives et questions de Taïwan | La rivalité Chine–États-Unis est présentée comme l'un des facteurs structurants de la géopolitique contemporaine, avec des racines idéologiques et culturelles mais une nature avant tout nationale : la compétition pour le leadership mondial. Elle se déploie sur des terrains imbriqués — intelligence artificielle, semi-conducteurs, normes technologiques, infrastructures numériques, influence, spatial — qui constituent autant de leviers de puissance et de points de friction pour les chaînes d'approvisionnement et la normalisation technique. Trois angles sont mis en avant : les enseignements du sommet de Shenzhen et les opportunités qu'il ouvre à Pékin, la perception chinoise de l'Europe, et l'effet de l'arrivée au pouvoir de Donald Trump sur la fermeté de Pékin vis-à-vis de Taïwan. La contribution reste analytique et programmatique, sans données quantitatives ni indicateurs exploitables ; elle doit donc être lue comme un cadre d'interprétation, à croiser avec des sources primaires pour toute décision opérationnelle. | [https://www.iris-france.org/chine-etats-unis-vers-un-duel-pour-la-suprematie-mondiale/](https://www.iris-france.org/chine-etats-unis-vers-un-duel-pour-la-suprematie-mondiale/) |
| **Allemagne, Europe, Russie, Ukraine** | Défense et sécurité, industrie de défense, budget public | Réarmement allemand et tournant de la politique de défense de Berlin depuis 2022 | Depuis le début de la guerre en Ukraine, Berlin revendique un tournant radical de sa politique de défense. Le chancelier Friedrich Merz a promis de faire de la Bundeswehr « l'armée la plus puissante d'Europe sur le plan conventionnel », ambition qui se traduit par une nouvelle hausse majeure des dépenses militaires prévue pour 2027 et par une accélération de la modernisation des équipements. L'analyse, conduite dans le cadre des « mardis de l'IRIS » avec Jacques-Pierre Gougeon, spécialiste de l'Allemagne, interroge la notion d'« Allemagne surarmée » : au-delà du volume budgétaire, les questions portent sur la soutenabilité industrielle, les capacités de recrutement, la doctrine d'emploi et la cohérence avec les engagements OTAN et la défense européenne. Pour les acteurs économiques et industriels, ce réarmement redessine la demande en munitions, défense sol-air, véhicules blindés et technologies de commandement, et modifie l'équilibre de la base industrielle de défense européenne. | [https://www.iris-france.org/une-allemagne-surarmee-les-mardis-de-liris/](https://www.iris-france.org/une-allemagne-surarmee-les-mardis-de-liris/) |
| **Ukraine, Russie, Crimée, Mer d'Azov, Mer Noire** | Défense, logistique militaire, infrastructures de transport | Destruction du pont routier de Kertch : portée politique majeure, impact logistique contenu par l'adaptation des chaînes d'approvisionnement russes | L'opération ukrainienne du 17 novembre 2026 a détruit une partie du pont routier reliant la Crimée à la Russie, infrastructure achevée en 2018 pour matérialiser le contrôle russe sur la péninsule. Le succès est d'abord symbolique et politique : il intervient à la veille du déplacement de Vladimir Poutine en Chine pour un trilatéral très médiatisé avec les présidents Trump et Xi, et constitue une riposte tactique à une attaque russe antérieure contre les ponts Nord et Sud de Kyiv. Sur le plan matériel, les piles semblent largement intactes malgré des fissures, mais le remplacement de l'arche d'acier détruite est difficile : l'originale avait été construite à terre puis mise en flottaison, et les drones ukrainiens peuvent continuer à entraver les réparations, au point que la reconstruction annoncée par le Kremlin pourrait n'avoir qu'une utilité limitée. L'effet militaire devrait rester localisé, car la Russie a adapté ses chaînes d'approvisionnement méridionales : report du trafic sur le lien ferroviaire, lui-même attaqué et structurellement limité en capacité portante, et sur la route R-280 dite « Novorossiya Highway », plus longue, déjà dégradée et ciblée de façon récurrente par les drones ukrainiens, ce qui renchérit les coûts pour les transporteurs. Le résultat est une réduction nette des flux entrants et sortants de Crimée plutôt qu'un effondrement du dispositif russe. | [https://www.rusi.org/explore-our-research/publications/commentary/kerch-bridge-destruction-politically-embarrassing-logistically-contained](https://www.rusi.org/explore-our-research/publications/commentary/kerch-bridge-destruction-politically-embarrassing-logistically-contained) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| OpenSSF blog — 2026/11/24 | Open Source Security Foundation (OpenSSF) — Linux Foundation | 2026-11-24 | International (Japon / communauté mondiale) | OpenSSF blog — 2026/11/24 | Annonce de la création d'un groupe de travail national OpenSSF Japon destiné à connecter l'écosystème nippon (industriels, universités, administrations, mainteneurs de projets) aux initiatives mondiales de sécurisation de la chaîne d'approvisionnement logicielle. Il ne s'agit pas d'un texte réglementaire contraignant, mais d'un vecteur d'influence normative : les travaux de l'OpenSSF (Scorecard, SLSA, SBOM, guides de durcissement, bonnes pratiques de divulgation) alimentent de facto les référentiels utilisés pour démontrer la conformité au Cyber Resilience Act européen, aux exigences NIS2 et aux guides de l'ANSSI/BSI. La structuration d'un pôle japonais renforce la participation asiatique aux standards et peut accélérer l'adoption de pratiques de sécurité vérifiables par les fournisseurs japonais présents sur le marché européen. | [https://openssf.org/blog/2026/11/24/establishing-the-openssf-japan-working-group-connecting-japan-with-the-global-community-%e5%92%8c%e8%a8%b3%e6%97%a5%e6%9c%ac%e3%81%a8%e3%82%b0%e3%83%ad%e3%83%bc%e3%83%90%e3%83%ab%e3%82%92%e3%81%a4/](https://openssf.org/blog/2026/11/24/establishing-the-openssf-japan-working-group-connecting-japan-with-the-global-community-%e5%92%8c%e8%a8%b3%e6%97%a5%e6%9c%ac%e3%81%a8%e3%82%b0%e3%83%ad%e3%83%bc%e3%83%90%e3%83%ab%e3%82%92%e3%81%a4/) |
| OpenSSF blog — LFD126 — 2026/11/24 | OpenSSF / Linux Foundation (offre de formation LFD126) | 2026-11-24 | International | OpenSSF blog — LFD126 — 2026/11/24 | Lancement d'un cours (LFD126) portant sur la découverte et la correction de vulnérabilités assistées par IA. Aucune portée réglementaire directe, mais l'initiative s'inscrit dans le mouvement de professionnalisation exigé par les cadres européens (NIS2, CRA, DORA) qui imposent aux organisations de démontrer des compétences et des processus de gestion des vulnérabilités documentés. L'usage de l'IA pour le triage et la remédiation introduit toutefois des risques propres : faux positifs, hallucination de correctifs, fuite de code propriétaire vers des services tiers, et dépendance à des modèles non maîtrisés. | [https://openssf.org/blog/2026/11/24/just-launched-finding-and-fixing-vulnerabilities-using-ai-lfd126/](https://openssf.org/blog/2026/11/24/just-launched-finding-and-fixing-vulnerabilities-using-ai-lfd126/) |
| CELEX:32026D2619 — OJ L 2026/2619 | Conseil de l'Union européenne (décision CFSP 2026/2619 du 23 novembre 2026) | 2026-11-24 | Union européenne | CELEX:32026D2619 — OJ L 2026/2619 | Quatre textes européens distincts, sans disposition cyber directe pour la plupart, présentent une pertinence CTI indirecte. La résolution du Parlement européen sur ses propres états prévisionnels de recettes et de dépenses pour l'exercice 2027 (section I) est un texte budgétaire interne qui fixe le cadre des moyens alloués aux administrations parlementaires et pèse en amont sur les négociations de la procédure budgétaire annuelle avec le Conseil et la Commission ; les lignes votées conditionnent le financement des programmes numériques, de la cybersécurité institutionnelle et des agences (ENISA, CERT-EU) dans la trajectoire 2027 et préparent le CFP 2028-2034. La décision PESC soutenant l'amélioration de l'efficacité opérationnelle de l'OIAC, dans le prolongement de la stratégie européenne de 2003 contre la prolifération des armes de destruction massive et de la Convention sur les armes chimiques, est en vigueur et s'accompagne d'un financement d'actions de l'OIAC ; l'organisation est une cible historique d'opérations cyber et d'influence (attaques attribuées à des acteurs étatiques russes entre 2018 et 2020, campagnes de désinformation sur l'usage d'agents chimiques en Syrie et au Royaume-Uni), et tout renforcement de ses capacités accroît l'exposition de sa chaîne d'approvisionnement, de ses laboratoires partenaires et de ses experts. La résolution d'initiative sur la diplomatie océanique pour la compétitivité de la pêche et de l'aquaculture de l'UE, articulée autour de la PCP, de l'accord ONU sur les stocks chevauchants et du traité BBNJ, n'est pas contraignante mais porte une dimension de sécurité maritime (lutte contre la pêche INN, contrôle des flottes, transparence des activités en haute mer) reposant massivement sur des données de positionnement (AIS, VMS) et des registres de navires, sources notoirement exposées à la manipulation (AIS spoofing, falsification de pavillons, sociétés-écrans). Enfin, la résolution soutenant la résilience démocratique de l'Arménie, dans le contexte du rapprochement UE-Arménie (ANCE, loi arménienne du 26 mars 2025 ouvrant le processus d'adhésion, plan de résilience et de croissance UE-Arménie), non contraignante, inscrit cette résilience dans une logique de contre-ingérence (désinformation, pressions hybrides, cyberattaques contre les infrastructures et les processus électoraux, corruption et capture d'État) ; la dimension cyber y est implicite mais structurante, les plans de résilience financés par l'UE comportant systématiquement un volet cybersécurité et protection des infrastructures critiques. | [https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026BP0155](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026BP0155)<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026D2619](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026D2619)<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026IP0121](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026IP0121)<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026IP0162](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026IP0162) |
| IRIS — Note / papier de recherche, 24/11/2026 | IRIS (Institut de relations internationales et stratégiques) — analyse de politiques publiques européennes | 2026-11-24 | Union européenne | IRIS — Note / papier de recherche, 24/11/2026 | Analyse critique des conditions de préférence européenne introduites dans les financements de défense de l'UE (subventions EDIP, prêts SAFE). La règle impose une part minimale de coûts de composants européens, mais s'arrête au composant : les matières premières critiques contenues dans ces composants restent hors périmètre, alors que l'Europe dépend quasi totalement de pays tiers — au premier rang desquels la Chine — pour plusieurs d'entre elles. Le texte souligne le paradoxe d'une règle censée réduire la dépendance envers un allié (États-Unis) qui accroît la dépendance envers un concurrent stratégique. Il documente des précédents concrets : restrictions chinoises de 2025 sur les terres rares, le gallium et le germanium, et flambée des prix du tungstène en 2026. L'évaluation des instruments existants (règlement CRMA, plan d'action RESourceEU, régime de sécurité d'approvisionnement de l'EDIP) conclut qu'ils améliorent la connaissance des dépendances mais laissent la vérification de l'origine des matériaux et la réduction de l'exposition largement volontaires pour les entreprises financées. La recommandation porte sur le CFP 2028-2034 : conditionner les financements à une cartographie de la chaîne d'approvisionnement et à des méthodes émergentes de vérification d'origine, plus une diversification lorsque des alternatives existent. | [https://www.iris-france.org/extending-supply-chain-security-in-eu-defence-funding-from-components-to-raw-materials/](https://www.iris-france.org/extending-supply-chain-security-in-eu-defence-funding-from-components-to-raw-materials/) |
| RUSI Commentary — 24/11/2026 | RUSI (Royal United Services Institute) — commentaire d'analyse | 2026-11-24 | Europe / Ukraine / États-Unis | RUSI Commentary — 24/11/2026 | Commentaire stratégique sur la rupture ouverte entre la présidence ukrainienne et l'administration américaine, et sur la position intenable de l'Europe, sommée de choisir entre accompagner une trajectoire américaine vers un accord de paix jugé défavorable ou soutenir l'émancipation ukrainienne. Le texte retrace l'évolution des signaux : pressions sur les flux d'aide, restrictions imposées aux actions ukrainiennes contre les infrastructures énergétiques russes, frappes ukrainiennes sur des raffineries et sur le pont de Kertch, critiques publiques sur Starlink/Starshield. Aucune portée réglementaire, mais des implications directes pour la posture de sécurité européenne : dépendance aux capacités spatiales et de renseignement américaines, fragmentation des soutiens, risque d'accélération des programmes de défense européens et de révision des cadres d'exportation. | [https://www.rusi.org/explore-our-research/publications/commentary/gloves-come-zelensky-gives-trump-what-should-europe-do](https://www.rusi.org/explore-our-research/publications/commentary/gloves-come-zelensky-gives-trump-what-should-europe-do) |
| BleepingComputer — Turnitin incident disclosure | Turnitin (entreprise privée) — notification aux autorités et régulateurs cyber | 2026-11-24 | International (États-Unis et juridictions des clients) | BleepingComputer — Turnitin incident disclosure | Turnitin, plateforme d'intégrité académique revendiquant plus de 16 000 établissements et 71 millions d'étudiants, déclare une activité non autorisée sur une partie de ses systèmes exposés aux clients. La société indique avoir activé son plan de réponse à incident, mandaté des spécialistes externes et notifié les forces de l'ordre ainsi que les régulateurs cyber. Les systèmes resteraient pleinement opérationnels et la plateforme ne collecterait ni pièces d'identité gouvernementales ni informations financières institutionnelles. Points non divulgués, et donc à surveiller : la date de l'incident, la nature exacte des données accédées, le nombre de personnes affectées et le vecteur d'intrusion. Le cas illustre la montée en charge des obligations de notification (NIS2, DORA pour les prestataires financiers, RGPD pour les données personnelles, réglementations sectorielles américaines) et le risque réputationnel propre aux plateformes utilisées par des millions d'utilisateurs en milieu éducatif. | [https://www.bleepingcomputer.com/news/security/turnitin-discloses-cyberattack-affecting-customer-facing-systems/](https://www.bleepingcomputer.com/news/security/turnitin-discloses-cyberattack-affecting-customer-facing-systems/)<br>[https://infosec.exchange/@edwardk/117673145186099747](https://infosec.exchange/@edwardk/117673145186099747) |
| Le Monde — 24/11/2026 | Juridictions françaises / analyse de presse (Le Monde) | 2026-11-24 | France | Le Monde — 24/11/2026 | Article consacré à la question de la responsabilité bancaire dans les arnaques sentimentales (romance scams) aboutissant à des virements ou à des paiements autorisés par la victime. Le cœur du débat juridique est l'articulation entre l'obligation de remboursement des opérations de paiement non autorisées ou exécutées de manière défectueuse (régime DSP2, transposé en droit français) et l'exception d'autorisation de l'opération par le payeur, y compris lorsqu'elle résulte d'une manipulation psychologique. La jurisprudence est hétérogène : les banques invoquent l'authentification forte et l'absence d'anomalie détectable, tandis que les victimes invoquent le devoir de vigilance et de détection des opérations atypiques. L'enjeu pour les équipes fraude est la qualification de la « manipulation autorisée » (authorised push payment fraud) et la répartition de la charge de la preuve. | [https://www.lemonde.fr/argent/article/2026/11/24/arnaque-aux-sentiments-la-banque-doit-elle-rembourser-la-victime_6814746_1657007.html](https://www.lemonde.fr/argent/article/2026/11/24/arnaque-aux-sentiments-la-banque-doit-elle-rembourser-la-victime_6814746_1657007.html) |
| Le Monde — 24/11/2026 | Parquet de Paris (enquête judiciaire) — CHU de Guadeloupe (victime) | 2026-11-24 | France | Le Monde — 24/11/2026 | Ouverture d'une enquête par le parquet de Paris après la cyberattaque ayant visé le CHU de Guadeloupe. La saisine du parquet parisien est cohérente avec la pratique française pour les atteintes aux systèmes de traitement automatisé de données (STAD) et les extorsions impliquant des infrastructures critiques, en lien avec les sections spécialisées en cybercriminalité. Le cas s'inscrit dans la série continue d'attaques contre des établissements de santé français, secteur où l'impact est vital (annulation d'actes, dégradation des soins, exfiltration de données patients). Les qualifications pénales attendues tournent autour des articles 323-1 et suivants du code pénal (accès et entrave à un STAD), de l'extorsion et, le cas échéant, de l'association de malfaiteurs. En parallèle, les obligations de notification à l'ANSSI et à la CNIL s'appliquent, ainsi que la déclaration de violation de données au RGPD. | [https://www.lemonde.fr/pixels/article/2026/11/24/guadeloupe-le-parquet-de-paris-ouvre-une-enquete-a-la-suite-de-la-cyberattaque-contre-le-chu_6814735_4408996.html](https://www.lemonde.fr/pixels/article/2026/11/24/guadeloupe-le-parquet-de-paris-ouvre-une-enquete-a-la-suite-de-la-cyberattaque-contre-le-chu_6814735_4408996.html) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Services juridiques (cabinets d'avocats américains)** | Kegler, Brown, Hill & Ritter LLP et plusieurs cabinets d'avocats américains (Greenbaum Rowe Smith & Davis, Archer & Greiner, Jones Walker, Kutak Rock, Jackson Walker, A&O Shearman, Wachtell Lipton, Kirkland & Ellis, Latham & Watkins, Baker McKenzie, etc.) | Données clients confidentielles (dossiers de contentieux, opérations M&A, PI), documents internes, courriels, identifiants, données RH et financières. Le détail exact par victime n'est pas encore publié pour la plupart des entrées (« To be announced »). | Inconnu | [https://www.ransomlook.io//group/leakeddata](https://www.ransomlook.io//group/leakeddata)<br>`hxxps://www[.]ransomlook[.]io//group/leakeddata` |
| **Gouvernement / Renseignement (États-Unis)** | CIA et Office of the Director of National Intelligence (ODNI) — réseau d'open source intelligence non classifié | Données OSINT non classifiées : sources ouvertes, imagerie satellitaire commerciale, données de courtiers privés, éventuellement identifiants d'analystes et métadonnées de requêtes. Aucune donnée classifiée revendiquée comme compromise. | Inconnu | [https://www.securityweek.com/an-unclassified-cia-system-was-breached-in-a-cyberattack-ap-source-says/](https://www.securityweek.com/an-unclassified-cia-system-was-breached-in-a-cyberattack-ap-source-says/)<br>[https://social.vir.group/@analytics/117673814088806450](https://social.vir.group/@analytics/117673814088806450)<br>[https://social.thedemocracyadvocate.com/notes/atysr0py3w](https://social.thedemocracyadvocate.com/notes/atysr0py3w)<br>`hxxps://www[.]securityweek[.]com/an-unclassified-cia-system-was-breached-in-a-cyberattack-ap-source-says/`<br>`hxxps://social[.]vir[.]group/@analytics/117673814088806450`<br>`hxxps://social[.]thedemocracyadvocate[.]com/notes/atysr0py3w` |
| **Biotechnologies** | Gingko Bioworks Holdings | Non précisé publiquement. Périmètre potentiel : propriété intellectuelle biotech, données de recherche et de partenaires, données personnelles de collaborateurs. | Inconnu | [https://databreaches.net/2026/11/24/gingko-bioworks-holdings-issued-a-statement-on-october-8-about-a-data-breach-getting-an-update-from-them-has-been-difficult/](https://databreaches.net/2026/11/24/gingko-bioworks-holdings-issued-a-statement-on-october-8-about-a-data-breach-getting-an-update-from-them-has-been-difficult/)<br>`hxxps://databreaches[.]net/2026/11/24/gingko-bioworks-holdings-issued-a-statement-on-october-8-about-a-data-breach-getting-an-update-from-them-has-been-difficult/` |
| **Santé (hôpital privé, Hong Kong)** | Gleneagles Hospital Hong Kong (application My Gleneagles SmartHealth) | Données personnelles de patients : noms, numéros de documents d'identité, coordonnées. Données de santé potentiellement associées via l'application. | Inconnu | [https://databreaches.net/2026/11/24/hk-gleneagles-hospital-suspends-app-after-data-breach/](https://databreaches.net/2026/11/24/hk-gleneagles-hospital-suspends-app-after-data-breach/)<br>`hxxps://databreaches[.]net/2026/11/24/hk-gleneagles-hospital-suspends-app-after-data-breach/` |
| **Multi-secteurs (exposition de bases de données)** | Multiples (deux bases de données non liées exposant 3,5 milliards d'identifiants, mots de passe et documents) | Noms d'utilisateur, mots de passe (possiblement hachés ou en clair), documents et données personnelles associées, sur environ 3,5 milliards d'enregistrements. | 3500000000 | [https://databreaches.net/2026/11/24/two-unrelated-database-leaks-expose-3-5-billion-uusernames-passwords-and-documents/](https://databreaches.net/2026/11/24/two-unrelated-database-leaks-expose-3-5-billion-uusernames-passwords-and-documents/)<br>`hxxps://databreaches[.]net/2026/11/24/two-unrelated-database-leaks-expose-3-5-billion-uusernames-passwords-and-documents/` |
| **Gouvernement (services numériques de l'État du Colorado)** | État du Colorado — application myColorado | Données personnelles de résidents : identité, coordonnées, potentiellement documents officiels et identifiants de connexion. Jusqu'à 150 000 personnes concernées. | 150000 | [https://databreaches.net/2026/11/24/state-shuts-down-mycolorado-app-after-data-breach-up-to-150000-people-may-be-affected/](https://databreaches.net/2026/11/24/state-shuts-down-mycolorado-app-after-data-breach-up-to-150000-people-may-be-affected/)<br>`hxxps://databreaches[.]net/2026/11/24/state-shuts-down-mycolorado-app-after-data-breach-up-to-150000-people-may-be-affected/` |
| **Commerce de détail / e-commerce (musique et vidéo)** | Tower Records Japan (Tower Records Online, tower.jp) | Adresses e-mail, identifiants membres, hash de mots de passe (algorithme non précisé), noms, noms en kana, pseudonymes, dates de naissance, genres, codes postaux, adresses de livraison, noms de destinataires, numéros de téléphone. Aucune donnée bancaire impliquée selon la société. | 10 214 652 comptes (e-mail, ID membre, hash de mot de passe) ; 2 784 514 enregistrements membres (nom, kana, pseudonyme, date de naissance, genre, code postal) ; 776 953 enregistrements de livraison (adresse, destinataire, téléphone) | [https://japancyberwatch.com/articles/tower-records-japan-online-breach-password-hashes-2026](https://japancyberwatch.com/articles/tower-records-japan-online-breach-password-hashes-2026) |
| **Secteur public / renseignement gouvernemental** | CIA et ODNI — système d'analyse OSINT inter-agences (États-Unis) | Données non classifiées issues de sources ouvertes : jeux de données commerciaux, contenus de réseaux sociaux, imagerie satellite, et potentiellement des informations détenues par d'autres agences gouvernementales. Aucune donnée classifiée selon les responsables. | Non divulgué — données non classifiées issues d'un système d'analyse OSINT partagé CIA/ODNI ; d'autres agences fédérales pourraient être concernées | [https://thedemocracyadvocate.com/national-security/cia-hack/](https://thedemocracyadvocate.com/national-security/cia-hack/)<br>[https://mastodon.uno/@marcocc/117673616222572481](https://mastodon.uno/@marcocc/117673616222572481)<br>[https://www.cyberkendra.com/2026/11/cia-odni-breach-open-source-intelligence-system.html](https://www.cyberkendra.com/2026/11/cia-odni-breach-open-source-intelligence-system.html) |
| **Sport professionnel / divertissement** | LaLiga (Liga Nacional de Fútbol Profesional, Espagne) | Données personnelles de supporters de football (nature exacte non divulguée publiquement). | Non divulgué | [https://www.bleepingcomputer.com/news/security/spanish-laliga-confirms-hackers-stole-soccer-fans-personal-data/](https://www.bleepingcomputer.com/news/security/spanish-laliga-confirms-hackers-stole-soccer-fans-personal-data/) |
| **Télécommunications** | Bell Canada (Bell, Bell Aliant, Bell MTS, Virgin Plus, Lucky Mobile) | Noms et adresses postales, numéros de téléphone et adresses e-mail, numéros de compte, informations produits, dates et montants des derniers paiements, noms d'entreprise et intitulés de poste, informations de tickets de service, certaines adresses IP. Cartes de crédit et données bancaires non compromises selon Bell. | Non divulgué (nombre de clients affectés non communiqué) | [https://beyondmachines.net/event_details/bell-canada-confirms-data-breach-following-unauthorized-access-to-customer-information-i-b-d-w-0/gD2P6Ple2L](https://beyondmachines.net/event_details/bell-canada-confirms-data-breach-following-unauthorized-access-to-customer-information-i-b-d-w-0/gD2P6Ple2L) |
| **Secteur public / administration gouvernementale** | Gouvernement bulgare — Ministère de l'Innovation et de la Transformation numérique | Documents relatifs aux opérations du cabinet, rapports gouvernementaux, communications entre ministères et agences gouvernementales. Aucune donnée personnelle de citoyens compromise selon les autorités. | Plus de 130 Go de documents (environ 62 millions de pages) exfiltrés sur cinq ans ; nombre de personnes concernées non divulgué | [https://beyondmachines.net/event_details/bulgaria-confirms-government-data-breach-following-five-years-of-unauthorized-access-s-d-e-r-j/gD2P6Ple2L](https://beyondmachines.net/event_details/bulgaria-confirms-government-data-breach-following-five-years-of-unauthorized-access-s-d-e-r-j/gD2P6Ple2L) |
| **ONG / think tank (relations internationales)** | Carnegie Endowment for International Peace (via un prestataire tiers) | Informations relatives aux dons et aux donateurs (coordonnées et données de donation, périmètre exact non divulgué). | Non divulgué | [https://therecord.media/carnegie-endowment-data-breach](https://therecord.media/carnegie-endowment-data-breach) |
| **Veille / Média cyber** | N/A — source de veille (threatintel.cc) | Aucune donnée compromise identifiée. | Inconnu | [https://infosec.exchange/@edwardk/117673195701146941](https://infosec.exchange/@edwardk/117673195701146941) |
| **Multi-secteur (finance, santé, gouvernement, technologie)** | Organisations ciblées par ARTEX (secteurs financier, santé, gouvernemental et technologique) | Aucune donnée spécifique compromise dans cet avis ; risque d'exfiltration de données sensibles sur les organisations ciblées. | Inconnu | [https://www.foxnews.com/tech/fbi-warns-ai-hackers-breach-systems-under-3-hours](https://www.foxnews.com/tech/fbi-warns-ai-hackers-breach-systems-under-3-hours)<br>[https://infosec.exchange/@edwardk/117673123783834061](https://infosec.exchange/@edwardk/117673123783834061) |
| **** | Fournisseurs d'inférence IA (Phala, Together AI, Novita, Atlas Cloud, OpenRouter, MiniMax) |  | Inconnu | [https://www.securityweek.com/ai-inference-providers-failed-to-detect-hacking-and-prompt-theft-says-dragos/](https://www.securityweek.com/ai-inference-providers-failed-to-detect-hacking-and-prompt-theft-says-dragos/)<br>[https://infosec.exchange/@edwardk/117673122159068938](https://infosec.exchange/@edwardk/117673122159068938) |
| **** | Cleverbridge |  | Inconnu | [https://www.bleepingcomputer.com/news/security/cleverbridge-warns-hackers-stole-credit-card-numbers-cvvs-in-data-breach/](https://www.bleepingcomputer.com/news/security/cleverbridge-warns-hackers-stole-credit-card-numbers-cvvs-in-data-breach/)<br>[https://infosec.exchange/@edwardk/117673120657642486](https://infosec.exchange/@edwardk/117673120657642486) |
| **Énergie / Services publics (infrastructure critique)** | Korea Electric Power Corporation (KEPCO) | KEPCO ON : noms, adresses, téléphones, identifiants uniques, numéros clients, numéros et détails de cartes, noms de banques, numéros de comptes bancaires, titulaires, détails de facturation. SRM : noms, identifiants uniques, e-mails, adresses d'entreprise, affiliations, identifiants employés, téléphones ; documents d'appels d'offres et contrats revendiqués. | 1520248 | [https://www.securityweek.com/1-5-million-impacted-by-data-breach-at-south-korean-electric-company-kepco/](https://www.securityweek.com/1-5-million-impacted-by-data-breach-at-south-korean-electric-company-kepco/)<br>[https://infosec.exchange/@edwardk/117671863251567588](https://infosec.exchange/@edwardk/117671863251567588) |
| **Restauration / Retail (application mobile)** | McDonald's Japan | Historique d'achat, adresses IP, données de localisation des appareils mobiles, identifiants de gestion client ; pas de noms, e-mails, téléphones ni données de cartes selon l'entreprise. | Inconnu | [https://www.bleepingcomputer.com/news/security/mcdonalds-japan-data-breach-exposes-customer-location-information/](https://www.bleepingcomputer.com/news/security/mcdonalds-japan-data-breach-exposes-customer-location-information/)<br>[https://infosec.exchange/@edwardk/117671861877254421](https://infosec.exchange/@edwardk/117671861877254421) |
| **Secteur public – forces de l'ordre et institutions fédérales (États-Unis)** | Federal Bureau of Investigation – National Crime Information Center (NCIC) | Non confirmé publiquement. Périmètre potentiel : données d'enquêtes, mandats et avis de recherche, fiches de personnes disparues, notes de prudence, données personnelles de personnes impliquées dans des procédures. | Inconnu | [https://theperimetersite.com/report/520](https://theperimetersite.com/report/520)<br>[https://infosec.exchange/@theperimetersite/117672706339154248](https://infosec.exchange/@theperimetersite/117672706339154248)<br>[https://therecord.media/fbi-cyberattack-data-breach](https://therecord.media/fbi-cyberattack-data-breach)<br>[https://infosec.exchange/@edwardk/117670875760175889](https://infosec.exchange/@edwardk/117670875760175889) |
| **Commerce de détail – musique et divertissement** | Tower Records | Non détaillé publiquement. Périmètre probable : identifiants de comptes clients, adresses e-mail, données de commande et éventuellement données de livraison. | 11000000 | [https://theperimetersite.com/report/520](https://theperimetersite.com/report/520)<br>[https://infosec.exchange/@theperimetersite/117672706339154248](https://infosec.exchange/@theperimetersite/117672706339154248) |
| **Multi-secteurs : vérification d'identité, services publics numériques, énergie** | Écosystème multi-victimes (IDScan, myColorado, KEPCO) – revendications ShinyHunters | Selon les victimes citées : documents d'identité et pièces justificatives (IDScan), données de résidents (myColorado), données personnelles de clients (KEPCO). Détail non confirmé pour chaque dossier. | Inconnu | [https://theperimetersite.com/report/521](https://theperimetersite.com/report/521)<br>[https://infosec.exchange/@theperimetersite/117673585526604967](https://infosec.exchange/@theperimetersite/117673585526604967) |
| **Distribution – composants électroniques et robotique (France)** | GoTronic | Adresses e-mail (328 000). Nature exacte des autres données (identité, adresse postale, historique de commande, données de paiement) non confirmée à ce stade. | 328000 | [https://infonewscyber.fr/info/gotronic-328-000-adresses-email-en-fuite-apres-une-cyberattaque-137ea9852f99537c](https://infonewscyber.fr/info/gotronic-328-000-adresses-email-en-fuite-apres-une-cyberattaque-137ea9852f99537c)<br>[https://infosec.exchange/@infonewscyber/117673323808614260](https://infosec.exchange/@infonewscyber/117673323808614260) |
| **Services financiers / e-commerce B2B – cartes cadeaux et top-up numériques** | GlobeTopper (groupe iQSTEL) | Clés API et clés d'intégration de clients professionnels ; cartes cadeaux pour environ 70 000 USD rachetées frauduleusement ; accès éventuel à des données personnelles, de paiement ou fournisseurs en cours d'investigation. | Inconnu | [https://www.helpnetsecurity.com/2026/11/24/globetopper-breach-gift-cards/](https://www.helpnetsecurity.com/2026/11/24/globetopper-breach-gift-cards/)<br>[https://infosec.exchange/@edwardk/117670875892982802](https://infosec.exchange/@edwardk/117670875892982802) |
| **Recherche en sécurité des données – applicable à tous secteurs (IA générative en entreprise)** | Entreprise fictive de l'étude Cyberhaven Labs – agents IA génératifs | Données de conseil confidentielles (revue de conseil), données clients (revenus et usage par client, liste de 63 clients), indicateurs financiers (ARR produit, nombre exact de clients). | Inconnu | [https://siliconangle.com/2026/11/23/ai-agents-leaked-confidential-data-in-87-of-100-test-runs-cyberhaven-finds/](https://siliconangle.com/2026/11/23/ai-agents-leaked-confidential-data-in-87-of-100-test-runs-cyberhaven-finds/)<br>[https://infosec.exchange/@edwardk/117670871916488749](https://infosec.exchange/@edwardk/117670871916488749) |
| **Mobile / grand public – écosystème Android** | Utilisateurs Android – 50 modèles de 10 constructeurs (37 modèles exposés) | Extraits de conversations tenues en haut-parleur (appels, messages vocaux) reconstruits à partir des métadonnées gyroscopiques de la caméra ; données de mouvement à haute fréquence. | Inconnu | [https://cyberinsider.com/android-camera-metadata-speakerphone-speech-leak/](https://cyberinsider.com/android-camera-metadata-speakerphone-speech-leak/)<br>[https://infosec.exchange/@edwardk/117670870362630972](https://infosec.exchange/@edwardk/117670870362630972) |
| **Services financiers / Paiement** |  | Données de réservation et de voyage de clients premium (rappels de réservation, statut client, coordonnées associées) ; pas de numéros de carte selon Visa. | 6000 | [https://www.youtube.com/watch?v=JcdnJgmiuQ8](https://www.youtube.com/watch?v=JcdnJgmiuQ8) |
| **Intelligence artificielle / Cloud (fournisseurs d'inférence)** |  | Prompts clients et échantillons de prompts stockés ; clés AWS et identifiants présents dans les requêtes ; données métier potentiellement copiées avec les requêtes légitimes. | Inconnu |  |
| **E-commerce / Plateforme de paiement et d'abonnement** |  | Numéros de cartes bancaires, dates d'expiration, codes de sécurité CVV ; données clients associées non précisées. | Inconnu |  |
| **Commerce media / adtech (selon la revendication de l'acteur)** | Company #265 (entité non identifiée, France) | Non confirmé. Périmètre allégué : données de campagnes publicitaires, analyses d'audience, relations commerciales et éventuels identifiants d'intégration. | Inconnu | [https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Matchbook3469/117672886204149587](https://mastodon.social/@Matchbook3469/117672886204149587)<br>[https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/](https://www.yazoul.net/intel/claim/2026-11-23-company-265-ransomware-claim-by-n0n-nov-2026/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-104868** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Débordement d'entier (integer overflow) lors de l'analyse de fichiers DWG, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de travail de l'utilisateur AutoCAD, avec les privilèges de ce dernier. Risque de vol de données de conception, de déploiement de malware et de pivot vers les partages réseau accessibles depuis le poste. | None | Appliquer la mise à jour Autodesk référencée dans l'avis adsk-sa-2026-0021. En attendant, restreindre l'ouverture de fichiers DWG non fiables, activer les protections EDR sur acad.exe et sensibiliser les utilisateurs au risque des fichiers de conception piégés. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1148/](http://www.zerodayinitiative.com/advisories/ZDI-26-1148/) |
| **CVE-2026-85648** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Débordement de buffer basé sur le tas (heap-based buffer overflow) lors de l'analyse de fichiers DDS, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de l'utilisateur, avec risque de compromission du poste de conception, de vol de propriété intellectuelle et de mouvement latéral vers les partages de fichiers. | None | Installer la mise à jour Autodesk adsk-sa-2026-0021. Restreindre l'ouverture de fichiers DDS non fiables, surveiller les crashs d'acad.exe et maintenir une protection EDR active sur les postes CAO. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1147/](http://www.zerodayinitiative.com/advisories/ZDI-26-1147/) |
| **CVE-2026-85647** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Débordement de buffer basé sur le tas (heap-based buffer overflow) lors de l'analyse de fichiers DWG, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de travail, compromission potentielle des données de conception et pivot vers les ressources réseau accessibles. | None | Appliquer la mise à jour Autodesk adsk-sa-2026-0021, filtrer les fichiers DWG entrants, surveiller les crashs d'acad.exe et maintenir une détection EDR sur les processus CAO. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1146/](http://www.zerodayinitiative.com/advisories/ZDI-26-1146/) |
| **CVE-2026-85646** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Débordement de buffer basé sur le tas (heap-based buffer overflow) lors de l'analyse de fichiers DWF, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de l'utilisateur, avec risque de vol de documents de conception, de déploiement de malware et de mouvement latéral. | None | Appliquer la mise à jour Autodesk adsk-sa-2026-0021, restreindre l'ouverture de fichiers DWF non fiables et surveiller les comportements anormaux des visionneuses. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1145/](http://www.zerodayinitiative.com/advisories/ZDI-26-1145/) |
| **CVE-2026-84855** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Débordement de buffer basé sur le tas (heap-based buffer overflow) lors de l'analyse de fichiers DGN, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de travail, compromission des données de conception et risque de pivot vers les partages réseau. | None | Appliquer la mise à jour Autodesk adsk-sa-2026-0021, filtrer les fichiers DGN entrants et surveiller les comportements anormaux d'AutoCAD. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1144/](http://www.zerodayinitiative.com/advisories/ZDI-26-1144/) |
| **CVE-2026-77944** | 3.3 | N/A | FALSE | Autodesk AutoCAD | Divulgation d'informations : fuite de réponses NTLM lors de l'analyse de fichiers DXF (défaut d'application d'un mécanisme de protection) | Divulgation du hash de réponse NTLM de l'utilisateur courant, exploitable pour du relais NTLM, du cracking hors ligne ou du mouvement latéral. Impact direct limité mais risque accru en environnement non segmenté. | None | Appliquer la mise à jour Autodesk adsk-sa-2026-0021, bloquer les flux SMB sortants vers Internet, désactiver NTLMv1 et activer la signature SMB ainsi que la protection EPA. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1142/](http://www.zerodayinitiative.com/advisories/ZDI-26-1142/) |
| **CVE-2026-77943** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Écriture hors limites (out-of-bounds write) lors de l'analyse de fichiers DXF, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de travail, avec risque de compromission des données de conception et de pivot vers les ressources réseau accessibles. | None | Appliquer la mise à jour Autodesk adsk-sa-2026-0021, restreindre l'ouverture de fichiers DXF non fiables et surveiller les comportements anormaux d'AutoCAD. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1141/](http://www.zerodayinitiative.com/advisories/ZDI-26-1141/) |
| **CVE-2026-77942** | 7.8 | N/A | FALSE | Autodesk AutoCAD | Écriture hors limites (out-of-bounds write) lors de l'analyse de fichiers IES, conduisant à une exécution de code à distance | Exécution de code arbitraire sur le poste de travail, avec risque de compromission des données de conception et de pivot vers les ressources réseau accessibles. | None | Appliquer la mise à jour Autodesk adsk-sa-2026-0021, restreindre l'ouverture de fichiers IES non fiables et surveiller les comportements anormaux d'AutoCAD. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1140/](http://www.zerodayinitiative.com/advisories/ZDI-26-1140/) |
| **CVE-2026-123903** | 9.8 | N/A | FALSE | VMware vCenter Server (service VMware Directory Service – vmdir), VMware Cloud Foundation, VMware vSphere Foundation, VMware ESX, Workstation, Fusion, VMware Tools et Avi Load Balancer | Contournement d'authentification (CWE-287) dans le service d'annuaire vmdir | Compromission totale du plan de contrôle de virtualisation : accès non authentifié à vCenter, création de comptes administrateur SSO, vol de données, déplacement latéral vers les hôtes ESX et l'ensemble des VM hébergées, persistance via forge de jetons d'authentification. L'impact est maximal pour les environnements exposant l'interface de gestion vCenter sur Internet ou sur des réseaux non cloisonnés. | None | Appliquer les correctifs : VMware Cloud Foundation / vSphere Foundation 9.1.x → 9.1.2 ; 9.0.x → 9.0.2.0300 ; vCenter 8.0 → 8.0 U3m ; vCenter 7.0 → contacter le support Broadcom (support étendu) ; VCF 5.x → 5.2.5 ; Telco Cloud Platform/Infrastructure → vCenter 8.0 U3m. En attendant, restreindre l'accès réseau à vCenter (liste blanche d'IP, bastion, VPN), désactiver les accès Internet au portail de gestion, activer le MFA sur les comptes SSO, auditer les comptes administrateur et surveiller les créations de comptes. Vérifier également l'application des correctifs de CVE-2026-123904 et des trois CVE de déni de service. | [https://thehackernews.com/2026/11/vmware-vcenter-hit-by-another-critical.html](https://thehackernews.com/2026/11/vmware-vcenter-hit-by-another-critical.html)<br>[https://securityaffairs.com/203931/security/vmware-patches-critical-vcenter-authentication-bypass-and-esx-flaws.html](https://securityaffairs.com/203931/security/vmware-patches-critical-vcenter-authentication-bypass-and-esx-flaws.html) |
| **CVE-2026-134624** | 9.3 | N/A | TRUE | N-able MailAssure et SpamExperts (composant de vérification de connexion de synchronisation LDAP), versions antérieures à 20261121.1943 | Falsification de requête côté serveur (SSRF) – CWE-918 | Reconnaissance et atteinte de services internes non exposés à Internet, contournement du cloisonnement réseau, vol potentiel de données d'annuaire ou de messagerie, perturbation de service pour les clients hébergés. Le caractère authentifié requis limite l'exposition aux titulaires de comptes API, mais ceux-ci peuvent être obtenus par fuite de clé ou par compromission d'un client. | Active | Mettre à jour vers la version 20261121.1943 ou ultérieure. Révoquer et régénérer les clés API et identifiants LDAP de synchronisation. Restreindre les flux sortants des serveurs MailAssure vers les seuls services internes nécessaires. Surveiller les appels à l'endpoint de vérification de connexion LDAP et les connexions vers des hôtes/ports internes inhabituels. Pour les clients hébergés, vérifier auprès de N-able l'état de remédiation de l'instance. | [https://thehackernews.com/2026/11/hackers-exploit-n-able-mailassure-flaw.html](https://thehackernews.com/2026/11/hackers-exploit-n-able-mailassure-flaw.html)<br>[https://securityaffairs.com/203882/hacking/u-s-cisa-adds-n-able-mailassure-and-project-monai-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/203882/hacking/u-s-cisa-adds-n-able-mailassure-and-project-monai-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-133968** | 9.8 | N/A | TRUE | Project MONAI – MONAI Label, versions jusqu'à 0.8.5 incluse (endpoint PUT /datastore/image, paramètre image) | Traversée de répertoire (CWE-22) menant à une exécution de code à distance | Exécution de code arbitraire avec privilèges root sur les serveurs hébergeant MONAI Label, accès et modification potentielle de jeux de données d'imagerie médicale (données de santé sensibles), pivotement vers les réseaux universitaires adjacents et implantation de persistance. L'automatisation par agents IA réduit drastiquement le temps entre la découverte et l'exploitation. | Active | Mettre à jour vers MONAI Label 0.8.6. À défaut, désactiver l'endpoint PUT /datastore/image ou restreindre l'accès au service par authentification et filtrage réseau. Ne pas exposer MONAI Label sur Internet, exécuter le service avec un compte non privilégié et en conteneur isolé, surveiller l'apparition de fichiers sitecustomize.py/usercustomize.py et les connexions sortantes depuis les processus Python. | [https://thehackernews.com/2026/11/hackers-exploit-n-able-mailassure-flaw.html](https://thehackernews.com/2026/11/hackers-exploit-n-able-mailassure-flaw.html)<br>[https://securityaffairs.com/203882/hacking/u-s-cisa-adds-n-able-mailassure-and-project-monai-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/203882/hacking/u-s-cisa-adds-n-able-mailassure-and-project-monai-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-134401** | 9.6 | N/A | FALSE | Google Chrome (Windows, macOS, Linux, Android) et Chrome Extended Stable, versions antérieures à 158.0.8127.88/.89, 158.0.8127.92 (Android) et 156.0.8078.114 (Extended Stable) | Validation d'entrée incorrecte (CWE-20) dans le composant Variations, permettant une exécution de code hors du bac à sable | Exécution de code arbitraire sur le poste de travail de la victime après simple visite d'une page web malveillante, avec franchissement du bac à sable : vol de données, vol de sessions et de cookies, installation de malware, mouvement latéral depuis le poste utilisateur. Les postes non patchés constituent une surface d'attaque de premier choix pour les campagnes de drive-by et de malvertising. | None | Mettre à jour Chrome vers 158.0.8127.88/.89 (Windows/macOS), 158.0.8127.88 (Linux), 158.0.8127.92 (Android) et Extended Stable 156.0.8078.114. Vérifier l'application effective des mises à jour (redémarrage du navigateur), imposer la mise à jour via GPO/MDM, restreindre les extensions non approuvées et surveiller les processus enfants lancés par le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1608/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1608/)<br>[https://socprime.com/blog/cve-2026-134401-critical-google-chrome-flaw-can-enable-code-execution-outside-the-sandbox/](https://socprime.com/blog/cve-2026-134401-critical-google-chrome-flaw-can-enable-code-execution-outside-the-sandbox/) |
| **CVE-2026-91483** | 7.8 | N/A | FALSE | Oracle Outside In Technology | Integer overflow lors du parsing de fichiers PNG conduisant à une exécution de code à distance (CWE-190) | Exécution de code arbitraire dans le contexte du processus appelant le SDK, pouvant mener à la compromission complète de l'application hôte (serveur de conversion, passerelle mail, moteur d'indexation) et servir de point d'entrée pour un mouvement latéral. | Theoretical | Appliquer le correctif Oracle Critical Patch Update d'octobre 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpuoct2026[.]html). En attendant, filtrer les fichiers PNG non sollicités, restreindre les privilèges des services utilisant le SDK et isoler les serveurs de conversion. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1154/](http://www.zerodayinitiative.com/advisories/ZDI-26-1154/) |
| **CVE-2026-91459** | 7.8 | N/A | FALSE | Oracle Outside In Technology | Écriture hors limites (out-of-bounds write) lors du parsing de fichiers BMP conduisant à une exécution de code à distance (CWE-787) | Exécution de code arbitraire dans le contexte du processus hôte, avec compromission potentielle du service de conversion et pivot vers les systèmes adjacents. | Theoretical | Appliquer le correctif Oracle Critical Patch Update d'octobre 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpuoct2026[.]html), filtrer les fichiers BMP non fiables et restreindre les privilèges des services utilisant le SDK. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1153/](http://www.zerodayinitiative.com/advisories/ZDI-26-1153/) |
| **CVE-2026-91460** | 7.8 | N/A | FALSE | Oracle Outside In Technology | Écriture hors limites (out-of-bounds write) lors du parsing de fichiers TIFF conduisant à une exécution de code à distance (CWE-787) | Exécution de code arbitraire dans le contexte du processus hôte, compromission potentielle du service de conversion et pivot vers les systèmes adjacents. | Theoretical | Appliquer le correctif Oracle Critical Patch Update d'octobre 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpuoct2026[.]html), filtrer les fichiers TIFF non fiables et restreindre les privilèges des services utilisant le SDK. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1152/](http://www.zerodayinitiative.com/advisories/ZDI-26-1152/) |
| **CVE-2026-91457** | 7.8 | N/A | FALSE | Oracle Outside In Technology | Écriture hors limites (out-of-bounds write) lors du parsing de fichiers BMP conduisant à une exécution de code à distance (CWE-787) | Exécution de code arbitraire dans le contexte du processus hôte, compromission du service de conversion et pivot latéral possible. | Theoretical | Appliquer le correctif Oracle Critical Patch Update d'octobre 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpuoct2026[.]html), filtrer les fichiers BMP non fiables et restreindre les privilèges des services utilisant le SDK. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1151/](http://www.zerodayinitiative.com/advisories/ZDI-26-1151/) |
| **CVE-2026-91458** | 7.8 | N/A | FALSE | Oracle Outside In Technology | Débordement de buffer sur la pile (stack-based buffer overflow) lors du parsing de fichiers XLSX conduisant à une exécution de code à distance (CWE-121) | Exécution de code arbitraire dans le contexte du processus hôte, compromission du service de conversion et pivot latéral possible. | Theoretical | Appliquer le correctif Oracle Critical Patch Update d'octobre 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpuoct2026[.]html), filtrer les classeurs XLSX non fiables, convertir les documents dans une sandbox et restreindre les privilèges des services utilisant le SDK. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1150/](http://www.zerodayinitiative.com/advisories/ZDI-26-1150/) |
| **CVE-2026-123340** | 9.6 | N/A | FALSE | Copeland XWEB Pro (firmware antérieur à 1.16.1) | Injection de commandes OS (CWE-78) permettant l'exécution de commandes arbitraires en root | Exécution de commandes arbitraires en root sur le contrôleur, permettant la modification des paramètres de supervision, la désactivation des alarmes, la perturbation des systèmes de réfrigération et l'utilisation de l'équipement comme point d'appui dans le réseau OT. | Theoretical | Mettre à jour vers XWEB Pro 1.16.1 (hxxps://webapps[.]copeland[.]com/dixell/Content/Pages/SystemSoftwareUpdate/XWEB-PRO/Changelog_XWEB-PRO_v[.]1[.]16[.]1_EN[.]pdf), restreindre l'exposition réseau de l'interface web, renforcer les comptes à privilèges et surveiller les journaux d'accès. | [https://cvefeed.io/vuln/detail/CVE-2026-123340](https://cvefeed.io/vuln/detail/CVE-2026-123340) |
| **CVE-2026-123216** | 9.6 | N/A | FALSE | Copeland XWEB Pro (firmware antérieur à 1.16.1) | Injection de commandes OS (CWE-78) permettant l'exécution de commandes arbitraires en root | Exécution de commandes arbitraires en root sur le contrôleur, modification des paramètres de supervision, perturbation des systèmes de réfrigération et pivot dans le réseau OT. | Theoretical | Mettre à jour vers XWEB Pro 1.16.1 (hxxps://webapps[.]copeland[.]com/dixell/Content/Pages/SystemSoftwareUpdate/XWEB-PRO/Changelog_XWEB-PRO_v[.]1[.]16[.]1_EN[.]pdf), restreindre l'exposition réseau de l'interface web, renforcer les comptes à privilèges et surveiller les journaux d'accès. | [https://cvefeed.io/vuln/detail/CVE-2026-123216](https://cvefeed.io/vuln/detail/CVE-2026-123216) |
| **CVE-2026-123215** | 9.8 | N/A | FALSE | Copeland XWEB Pro (firmware antérieur à 1.16.1) | Absence d'authentification pour une fonction critique (CWE-306) | Accès non authentifié à des fonctions critiques du contrôleur, modification des paramètres de supervision, désactivation d'alarmes et perturbation des systèmes de réfrigération ; l'équipement peut servir de point d'appui dans le réseau OT. | Theoretical | Mettre à jour vers XWEB Pro 1.16.1 ou ultérieur (hxxps://webapps[.]copeland[.]com/dixell/Content/Pages/SystemSoftwareUpdate/XWEB-PRO/Changelog_XWEB-PRO_v[.]1[.]16[.]1_EN[.]pdf), restreindre immédiatement l'exposition réseau de l'interface web et placer un contrôle d'authentification en frontal. | [https://cvefeed.io/vuln/detail/CVE-2026-123215](https://cvefeed.io/vuln/detail/CVE-2026-123215) |
| **CVE-2026-114205** | 9.9 | N/A | FALSE | ASUS Control Center Express | Autorisation inappropriée lors de la création d'utilisateurs (élévation de privilèges) | Compromission de la console de gestion du parc : création de comptes administrateurs illégitimes, déploiement d'agents ou de scripts malveillants sur les postes gérés, prise de contrôle à distance des endpoints. L'impact est potentiellement généralisé à l'ensemble du parc supervisé par ACC Express. | Theoretical | Appliquer la mise à jour publiée par ASUS (avis de sécurité ASUS). En attendant, restreindre l'exposition réseau de la console, désactiver les comptes inutilisés, imposer une authentification forte et auditer les journaux de création de comptes. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1157/](http://www.zerodayinitiative.com/advisories/ZDI-26-1157/) |
| **CVE-2026-114204** | 9.0 | N/A | FALSE | ASUS Control Center Express | Contournement d'authentification par clé cryptographique codée en dur (JWT) | Prise de contrôle administrative de la console de gestion du parc sans identifiants : accès aux configurations, aux agents déployés et aux postes supervisés. Risque élevé de mouvement latéral vers l'ensemble des systèmes gérés. | Theoretical | Appliquer le correctif ASUS, remplacer la clé codée en dur par un secret unique par installation, révoquer les jetons existants et restreindre l'accès réseau à la console. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1156/](http://www.zerodayinitiative.com/advisories/ZDI-26-1156/) |
| **CVE-2026-114202** | 10.0 | N/A | FALSE | ASUS Control Center Express | Contournement d'authentification par clé cryptographique codée en dur (score maximal) | Compromission totale et non authentifiée de la console de gestion du parc : accès administratif complet, capacité de déployer du code sur les postes gérés, d'exfiltrer des données de configuration et de désactiver les protections des endpoints. | Theoretical | Patch ASUS à appliquer en urgence, suppression de l'exposition Internet de la console, rotation des secrets, révocation des jetons et audit complet des actions administratives récentes. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1155/](http://www.zerodayinitiative.com/advisories/ZDI-26-1155/) |
| **CVE-2026-133453** | 9.1 | N/A | FALSE | AutoGPT Platform (Significant-Gravitas/AutoGPT) versions 0.7.1 à 0.10.0 | Contournement d'autorisation via clé contrôlée par l'utilisateur (CWE-639) | Détournement de la Marketplace et distribution de workflows malveillants sous une identité de confiance : exécution de code dans l'environnement des utilisateurs installant la fiche compromise, accès aux secrets et aux données de workspace, atteinte à la réputation du créateur et rupture de service des workflows non versionnés. | Theoretical | Mettre à jour vers AutoGPT Platform 0.11.0 ou ultérieur, vérifier l'intégrité des workflows après mise à jour, restreindre les droits de publication Marketplace et imposer une revue des soumissions. | [https://cvefeed.io/vuln/detail/CVE-2026-133453](https://cvefeed.io/vuln/detail/CVE-2026-133453)<br>[https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-mwr6-g4xq-4rvp](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-mwr6-g4xq-4rvp) |
| **CVE-2026-132264** | 8.1 | N/A | FALSE | AutoGPT Platform (Significant-Gravitas/AutoGPT) versions 0.6.63 à 0.10.0 | Erreur de changement de contexte de privilèges / autorisation incorrecte (CWE-270, CWE-863) | Élévation de privilèges fonctionnelle : une clé à périmètre restreint permet d'atteindre des ressources sensibles du compte (identifiants tiers, agents, fichiers) et d'exécuter du code dans le sandbox. Risque de fuite de secrets et de mouvement latéral vers les services tiers connectés. | Theoretical | Mettre à jour vers 0.11.0 ou ultérieur, appliquer le moindre privilège sur les clés API, restreindre l'usage d'EXECUTE_BLOCK et auditer les clés existantes. | [https://cvefeed.io/vuln/detail/CVE-2026-132264](https://cvefeed.io/vuln/detail/CVE-2026-132264)<br>[https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-8vm3-rxfw-5867](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-8vm3-rxfw-5867) |
| **CVE-2026-114934** | 9.3 | N/A | FALSE | Oracle PeopleSoft (classe PeopleSoftListeningConnector) | Falsification de requête côté serveur (SSRF, CWE-918) | Accès à des services internes non exposés, lecture de métadonnées d'infrastructure, contournement de la segmentation réseau et pivot vers des composants d'administration. Le SSRF peut servir de chaîne d'exploitation vers une exécution de code sur le serveur PeopleSoft. | Theoretical | Appliquer le correctif Oracle du CPU de novembre 2026, filtrer les flux sortants des serveurs PeopleSoft, restreindre l'exposition des endpoints PeopleSoft et surveiller les requêtes sortantes anormales. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1143/](http://www.zerodayinitiative.com/advisories/ZDI-26-1143/) |
| **CVE-2026-132779** | N/A | N/A | FALSE | F5 WAF for NGINX, NGINX App Protect WAF, NGINX Gateway Fabric, NGINX Ingress Controller, NGINX Open Source et NGINX Plus selon les versions listées par F5 | Déni de service à distance | Un attaquant distant peut provoquer un déni de service sur les composants F5/NGINX vulnérables, entraînant une indisponibilité des services exposés. | Theoretical | Appliquer les correctifs du bulletin F5 K000163947 ; mettre à jour vers les versions corrigées ; restreindre l'exposition des services vulnérables ; surveiller les journaux et les métriques de disponibilité. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1612/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1612/) |
| **CVE-2026-107494** | N/A | N/A | FALSE | OpenSSL versions 1.1.1x < 1.1.1zk, 3.0.x < 3.0.24, 3.5.x < 3.5.10, 4.0.x < 4.0.4 et 4.1.x < 4.1.1 | Déni de service à distance | Un attaquant distant peut provoquer un déni de service sur les services utilisant une version vulnérable d'OpenSSL. | Theoretical | Appliquer les correctifs du bulletin OpenSSL ; mettre à jour vers les versions corrigées ; restreindre l'exposition des services vulnérables ; surveiller les journaux et les métriques de disponibilité. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/) |
| **CVE-2026-121482** | N/A | N/A | FALSE | OpenSSL versions 1.1.1x < 1.1.1zk, 3.0.x < 3.0.24, 3.5.x < 3.5.10, 4.0.x < 4.0.4 et 4.1.x < 4.1.1 | Déni de service à distance | Un attaquant distant peut provoquer un déni de service sur les services utilisant une version vulnérable d'OpenSSL. | Theoretical | Appliquer les correctifs du bulletin OpenSSL ; mettre à jour vers les versions corrigées ; restreindre l'exposition des services vulnérables ; surveiller les journaux et les métriques de disponibilité. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/) |
| **CVE-2026-84785** | N/A | N/A | FALSE | OpenSSL versions 1.1.1x < 1.1.1zk, 3.0.x < 3.0.24, 3.5.x < 3.5.10, 4.0.x < 4.0.4 et 4.1.x < 4.1.1 | Déni de service à distance | Un attaquant distant peut provoquer un déni de service sur les services utilisant une version vulnérable d'OpenSSL. | Theoretical | Appliquer les correctifs du bulletin OpenSSL ; mettre à jour vers les versions corrigées ; restreindre l'exposition des services vulnérables ; surveiller les journaux et les métriques de disponibilité. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/) |
| **CVE-2026-84786** | N/A | N/A | FALSE | OpenSSL versions 1.1.1x < 1.1.1zk, 3.0.x < 3.0.24, 3.5.x < 3.5.10, 4.0.x < 4.0.4 et 4.1.x < 4.1.1 | Déni de service à distance | Un attaquant distant peut provoquer un déni de service sur les services utilisant une version vulnérable d'OpenSSL. | Theoretical | Appliquer les correctifs du bulletin OpenSSL ; mettre à jour vers les versions corrigées ; restreindre l'exposition des services vulnérables ; surveiller les journaux et les métriques de disponibilité. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1613/) |
| **CVE-2026-114938** | N/A | N/A | FALSE | Elasticsearch, Logstash, Kibana, Elastic Agent, Packetbeat et Elastic Cloud Enterprise selon les versions listées par Elastic | Exécution de code arbitraire à distance (Java4shell), élévation de privilèges et déni de service | Un attaquant peut exploiter Java4shell pour exécuter du code arbitraire à distance, élever ses privilèges ou provoquer un déni de service sur les composants Elastic vulnérables. | Theoretical | Appliquer les correctifs Elastic et mettre à jour vers les versions corrigées ; restreindre l'exposition des interfaces sensibles ; surveiller les journaux et les processus ; renforcer les contrôles d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1614/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1614/) |
| **CVE-2026-124284** | N/A | N/A | FALSE | Genetec Security Center | Contournement d'authentification | Un attaquant pourrait contourner l'authentification et accéder à des fonctionnalités ou données protégées de Security Center, avec un risque de compromission de la sécurité physique. | Theoretical | Appliquer le correctif Genetec ; restreindre l'exposition réseau ; renforcer l'authentification et la surveillance des accès ; vérifier les comptes et privilèges. | [https://cvefeed.io/vuln/detail/CVE-2026-124284](https://cvefeed.io/vuln/detail/CVE-2026-124284) |
| **CVE-2026-16663** | 8.4 | N/A | FALSE | MCUboot avec MCUBOOT_ENC_IMAGES et recovery série activés, y compris les versions avant v2.0.0 (v1.9.0 et v1.10.0) | Écriture hors limites pré-authentification (CWE-787) dans le déchiffrement d'image de recovery série | Un attaquant peut corrompre la mémoire du bootloader avant toute vérification de signature, potentiellement exécuter du code dans la racine de confiance du secure boot, contourner l'authentification des images et provoquer un déni de service. | Theoretical | Appliquer le correctif MCUboot/Zephyr dès disponibilité ; désactiver la recovery série chiffrée si non nécessaire ; restreindre l'accès physique aux interfaces de recovery ; vérifier l'intégrité des images de firmware. | [https://cvefeed.io/vuln/detail/CVE-2026-16663](https://cvefeed.io/vuln/detail/CVE-2026-16663) |
| **CVE-2026-136522** | 9.6 | N/A | FALSE | CubeWP Forms versions antérieures à 1.1.13 | XSS stockée non authentifiée (CWE-79) | Un attaquant non authentifié peut injecter du JavaScript stocké et, lorsqu'un administrateur consulte un lead, exécuter du code dans sa session wp-admin, créer un compte administrateur et prendre le contrôle du site. | Theoretical | Mettre à jour CubeWP Forms vers 1.1.13 ou ultérieure ; assainir toutes les entrées utilisateur ; échapper les sorties ; renforcer le WAF ; vérifier les comptes administrateur et les leads. | [https://cvefeed.io/vuln/detail/CVE-2026-136522](https://cvefeed.io/vuln/detail/CVE-2026-136522) |
| **CVE-2026-136455** | 8.8 | N/A | FALSE | borg-ui (versions antérieures à 2.4.1) | Escalade de privilèges via contrôle externe du chemin de fichier (CWE-73) | Élévation de privilèges d'un opérateur de dépôt vers administrateur applicatif, divulgation de secrets cryptographiques, accès à l'ensemble des données et configurations, et prise de contrôle totale de l'instance borg-ui. Le score CVSS 3.1 est de 8.8 (HIGH) et 8.7 en CVSS 4.0. | Theoretical | Mettre à jour borg-ui vers la version 2.4.1 ou ultérieure, appliquer un allow-listing sur le champ source_directories, restreindre l'accès à l'API backup-plan, régénérer la clé secrète HS256 et invalider les JWT existants. | [https://cvefeed.io/vuln/detail/CVE-2026-136455](https://cvefeed.io/vuln/detail/CVE-2026-136455)<br>[https://www.vulncheck.com/advisories/borg-ui-before-2.4.1-privilege-escalation-via-backup-plan-path-traversal](https://www.vulncheck.com/advisories/borg-ui-before-2.4.1-privilege-escalation-via-backup-plan-path-traversal)<br>[https://github.com/karanhudia/borg-ui/commit/b9cca22da2e9bb9d07c3fb7b2dd4c95f02964cc8](https://github.com/karanhudia/borg-ui/commit/b9cca22da2e9bb9d07c3fb7b2dd4c95f02964cc8) |
| **CVE-2026-135046** | 8.8 | N/A | FALSE | Plugin WordPress Store Exporter (woocommerce-exporter) jusqu'à la version 2.8.2 incluse | Cross-Site Request Forgery (CWE-352) | Exécution d'actions non autorisées dans le contexte d'un administrateur WordPress, pouvant conduire à l'exfiltration de données produits, commandes ou clients, voire à des modifications de configuration du site. Score CVSS 3.1 de 8.8 (HIGH). | None | Mettre à jour le plugin Store Exporter vers la dernière version disponible, vérifier régulièrement l'application des correctifs et restreindre l'accès à l'administration WordPress (WAF, authentification forte, restriction IP). | [https://cvefeed.io/vuln/detail/CVE-2026-135046](https://cvefeed.io/vuln/detail/CVE-2026-135046)<br>[https://patchstack.com/database/wordpress/plugin/woocommerce-exporter/vulnerability/wordpress-store-exporter-plugin-2-8-2-cross-site-request-forgery-csrf-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/woocommerce-exporter/vulnerability/wordpress-store-exporter-plugin-2-8-2-cross-site-request-forgery-csrf-vulnerability?_s_id=cve) |
| **CVE-2026-126695** | 8.7 | N/A | FALSE | TIBCO Control Plane 1.22.0 et TIBCO Control Tower 1.22.0 | Utilisation de mot de passe codé en dur (CWE-259) | Accès non autorisé aux consoles et API d'administration, divulgation d'informations sensibles sur l'infrastructure et les politiques de contrôle, et possibilité de modifications de configuration. Score CVSS 4.0 de 8.7 (HIGH). | Theoretical | Mettre à jour Control Plane et Control Tower vers les versions corrigées, supprimer les identifiants codés en dur des fichiers de configuration, mettre en place une gestion sécurisée des secrets et restreindre l'exposition réseau des interfaces d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-126695](https://cvefeed.io/vuln/detail/CVE-2026-126695)<br>[https://community.tibco.com/advisories/tibco-security-advisory-november-24-2026-tibco-control-plane-control-tower-cve-2026-126695-r234/](https://community.tibco.com/advisories/tibco-security-advisory-november-24-2026-tibco-control-plane-control-tower-cve-2026-126695-r234/) |
| **CVE-2026-112732** | 9.8 | N/A | FALSE | Microsoft Office Visio (Microsoft 365 Apps, Office 2024, Office 2021) | Double free conduisant à une exécution de code à distance (CWE-415) | Exécution de code arbitraire dans le contexte de l'utilisateur ouvrant le document, pouvant mener à la compromission complète du poste, au vol d'identifiants et à un point d'appui pour des mouvements latéraux. | Theoretical | Appliquer les mises à jour Microsoft publiées dans le guide MSRC pour CVE-2026-112732, bloquer les pièces jointes Visio non sollicitées et surveiller les exécutions anormales de VISIO.EXE. | [https://cvefeed.io/vuln/detail/CVE-2026-112732](https://cvefeed.io/vuln/detail/CVE-2026-112732)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-112732](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-112732) |
| **CVE-2026-86155** | 10.0 | N/A | FALSE | Apache Jena Fuseki jusqu'à la version 6.2.0 incluse | Server-Side Request Forgery via la validation SHACL (CWE-918) | Accès à des services internes non exposés, divulgation d'informations sensibles (y compris des jetons d'instance cloud), et possibilité de pivoter vers d'autres composants de l'infrastructure. | Theoretical | Mettre à jour Apache Jena Fuseki vers la version 6.3.0, restreindre les connexions sortantes du serveur et limiter l'accès aux endpoints de validation SHACL. | [https://cvefeed.io/vuln/detail/CVE-2026-86155](https://cvefeed.io/vuln/detail/CVE-2026-86155)<br>[https://lists.apache.org/thread.html/c26p602yxs8g5p6936o03ct7fwqvd90c](https://lists.apache.org/thread.html/c26p602yxs8g5p6936o03ct7fwqvd90c)<br>[http://www.openwall.com/lists/oss-security/2026/11/23/32](http://www.openwall.com/lists/oss-security/2026/11/23/32) |
| **CVE-2026-136441** | 9.8 | N/A | FALSE | Bytebase DBHub (serveur MCP) | Autorisation incorrecte conduisant à un contournement d'authentification (CWE-863) | Contournement complet de l'authentification sur les installations DBHub, accès non autorisé aux bases de données gérées et possibilité d'exécution de requêtes arbitraires sur celles-ci. | Theoretical | Appliquer les correctifs Bytebase, renforcer la logique d'autorisation et la validation du SQL non fiable, et restreindre l'exposition réseau du serveur MCP. | [https://cvefeed.io/vuln/detail/CVE-2026-136441](https://cvefeed.io/vuln/detail/CVE-2026-136441)<br>[https://www.zerodayinitiative.com/advisories/ZDI-26-1067/](https://www.zerodayinitiative.com/advisories/ZDI-26-1067/) |
| **CVE-2026-136434** | 9.8 | N/A | FALSE | Super Magic PHPSandbox | Injection de code / évasion de bac à sable (CWE-94) | Exécution de code arbitraire sur le serveur hébergeant le sandbox, compromission du compte de service, accès aux données et aux secrets de l'application, et pivot potentiel vers l'infrastructure interne. | Theoretical | Appliquer les correctifs éditeur, restreindre l'accès à l'endpoint PHPSandbox, renforcer la validation des entrées et l'isolation du bac à sable (utilisateur non privilégié, seccomp, AppArmor). | [https://cvefeed.io/vuln/detail/CVE-2026-136434](https://cvefeed.io/vuln/detail/CVE-2026-136434)<br>[https://www.zerodayinitiative.com/advisories/ZDI-26-1060/](https://www.zerodayinitiative.com/advisories/ZDI-26-1060/) |
| **CVE-2026-136412** | 9.2 | N/A | FALSE | OpenResty stream-lua-nginx-module (versions antérieures à 0.0.20rc4) | Use-after-free via l'itérateur de motif cosocket receiveuntil() (CWE-416) | Déni de service par crash répété des workers nginx, avec un risque de corruption mémoire pouvant, dans des conditions particulières, être détourné vers une exécution de code. | Theoretical | Mettre à jour stream-lua-nginx-module vers la version 0.0.20rc4 ou ultérieure, redémarrer les workers nginx et surveiller les redémarrages anormaux. | [https://cvefeed.io/vuln/detail/CVE-2026-136412](https://cvefeed.io/vuln/detail/CVE-2026-136412)<br>[https://www.vulncheck.com/advisories/openresty-stream-lua-nginx-module-before-0.0-20rc4-use-after-free-via-cosocket-receiveuntil](https://www.vulncheck.com/advisories/openresty-stream-lua-nginx-module-before-0.0-20rc4-use-after-free-via-cosocket-receiveuntil)<br>[https://github.com/openresty/stream-lua-nginx-module/commit/9591e20ab754e78437b7519053ff496aca25f531](https://github.com/openresty/stream-lua-nginx-module/commit/9591e20ab754e78437b7519053ff496aca25f531) |
| **CVE-2026-136411** | 9.8 | N/A | FALSE | BusyBox jusqu'à la version 1.38.0 (composant networking/tftp.c, démon tftpd) | Traversée de chemin absolu (CWE-36) permettant lecture/écriture arbitraire de fichiers | Lecture de fichiers sensibles (/etc/shadow, clés privées, configurations), écriture de fichiers arbitraires pouvant conduire à une compromission complète de l'équipement, déni de service et pivot vers les réseaux internes. | Theoretical | Mettre à jour BusyBox vers une version postérieure à 1.38.0 (commit b67f7b7d14ac98ca84491718d364b955d21a9cd5). Toujours démarrer tftpd avec un argument DIR explicite. Restreindre l'accès au service TFTP par filtrage réseau et segmentation. Désactiver tftpd lorsqu'il n'est pas strictement nécessaire et surveiller les journaux du service. | [https://cvefeed.io/vuln/detail/CVE-2026-136411](https://cvefeed.io/vuln/detail/CVE-2026-136411) |
| **CVE-2026-136410** | 9.5 | N/A | FALSE | Thymeleaf antérieur à 3.1.6.RELEASE | Contournement du mode d'expression restreint / injection d'expression (CWE-917) menant à une SSTI | Exécution de code arbitraire côté serveur, accès aux données applicatives et aux secrets de configuration, compromission complète de l'application Java et pivot vers les systèmes internes. | Theoretical | Mettre à jour vers Thymeleaf 3.1.6.RELEASE ou ultérieur. Assainir toutes les entrées utilisateur atteignant des contextes d'expression restreints. Revoir et restreindre l'usage des objets d'expression et des templates dynamiques. Ajouter un filtrage WAF sur les motifs d'expression. | [https://cvefeed.io/vuln/detail/CVE-2026-136410](https://cvefeed.io/vuln/detail/CVE-2026-136410) |
| **CVE-2026-136404** | 9.8 | N/A | FALSE | ntop n2n supernode versions 3.0 à 3.1.1 | Débordement de tampon sur la pile (CWE-121) via le champ token_size de REGISTER_SUPER_NAK | Fuite d'informations mémoire (ASLR bypass), exécution de code arbitraire sur le supernode, déni de service et compromission du réseau overlay géré par n2n. | Theoretical | Appliquer la mise à jour ntop n2n corrigeant la vulnérabilité (commit 854fbbe01bbf131bf4cb88f8450d7084267668e1). Valider l'intégrité de l'installation du supernode, restreindre son exposition réseau et surveiller les journaux du service. | [https://cvefeed.io/vuln/detail/CVE-2026-136404](https://cvefeed.io/vuln/detail/CVE-2026-136404) |
| **CVE-2026-135797** | 10.0 | N/A | FALSE | Volans NGFW Next-Generation Firewall r5.1 (composant SSLVPN Client, fichier sslvpn/sslvpn_client.php) | Injection de commandes OS (CWE-77 / CWE-78) via le paramètre img | Exécution de commandes arbitraires avec les privilèges du service web (souvent root), compromission totale du pare-feu, pivot vers les réseaux internes et interception du trafic. | Active | Assainir toutes les entrées utilisateur et appliquer les correctifs éditeur dès disponibilité. Restreindre l'accès au client SSLVPN aux adresses légitimes, surveiller le trafic réseau et envisager le remplacement ou l'isolation de l'équipement si aucun correctif n'est fourni. | [https://cvefeed.io/vuln/detail/CVE-2026-135797](https://cvefeed.io/vuln/detail/CVE-2026-135797) |
| **CVE-2026-131914** | N/A | N/A | FALSE | Non précisé dans la source (article dédié à CVE-2026-131914) | Contournement de contrôle anti-CSRF conduisant à une exécution de code à distance | Potentiellement exécution de code à distance sur l'application vulnérable, détournement d'actions administratives et compromission du serveur applicatif ; impact exact à confirmer. | Theoretical | Appliquer les correctifs éditeur dès publication, renforcer la validation serveur des jetons anti-CSRF, restreindre l'exposition des interfaces d'administration et surveiller les journaux applicatifs. | [https://thecyberthrone.in/2026/11/24/cve-2026-131914-anti-csrf-control-becomes-a-rce-entry-point/](https://thecyberthrone.in/2026/11/24/cve-2026-131914-anti-csrf-control-becomes-a-rce-entry-point/) |
| **CVE-2026-87268** | 7.8 | N/A | FALSE | Oracle VM VirtualBox 7.2.16 sur hôtes Windows | Contournement du durcissement de processus via le mécanisme de repli de chargement du .NET Framework (chargement d'assembly en mémoire) | Exécution de code dans le processus VirtualBox protégé, pouvant mener à la prise de contrôle de l'hyperviseur de type 2 et à une élévation de privilèges sur l'hôte Windows. | Active | Mettre à jour VirtualBox vers la version corrigée publiée par Oracle en septembre 2026. Restreindre les droits d'écriture dans les ruches de registre utilisateur, surveiller les détournements COM et durcir les politiques d'intégrité de code. | [https://thehackernews.com/2026/11/google-researcher-shows-how-single-bit.html](https://thehackernews.com/2026/11/google-researcher-shows-how-single-bit.html) |
| **CVE-2026-108398** | 8.8 | N/A | FALSE | Microsoft Windows (Windows 11 en mode S / UMCI), via le chemin de chargement du .NET Framework 4 | Contournement de fonctionnalité de sécurité (intégrité de code utilisateur) par chargement d'assembly .NET non fiable | Contournement de l'intégrité de code utilisateur et exécution de code non fiable dans des processus protégés (PPL), ouvrant la voie à une élévation de privilèges locale et à la neutralisation de protections de sécurité. | Theoretical | Appliquer le correctif Microsoft du 13 octobre 2026. Restreindre le chargement d'assemblies .NET non signés, durcir les politiques WDAC/UMCI et surveiller les détournements COM vers des assemblies utilisateur. | [https://thehackernews.com/2026/11/google-researcher-shows-how-single-bit.html](https://thehackernews.com/2026/11/google-researcher-shows-how-single-bit.html) |
| **CVE-2026-82981** | 8.7 | N/A | FALSE | WHMCS (plateforme de facturation et d'automatisation pour hébergeurs), versions antérieures aux correctifs 9.0.10, 8.13.8 et 9.1.2 | Injection SQL non authentifiée dans le panier (CWE-89) | Exposition de données personnelles clients, fuite de hachages de mots de passe administrateurs (cassage hors ligne ultérieur), compromission potentielle de l'ensemble de la plateforme de facturation. | Theoretical | Mettre à jour vers 9.0.10, 8.13.8 ou 9.1.2 (les installations 8.0 à 8.12 doivent migrer vers une version supportée). Les installations WHMCS Cloud sont mises à jour automatiquement. Restreindre l'accès au panier, déployer un WAF et surveiller les journaux SQL. | [https://thehackernews.com/2026/11/whmcs-sql-injection-flaw-could-expose.html](https://thehackernews.com/2026/11/whmcs-sql-injection-flaw-could-expose.html) |
| **CVE-2026-82979** | 7.1 | N/A | FALSE | WHMCS, versions antérieures aux correctifs 9.0.10, 8.13.8 et 9.1.2 (espace client) | Injection SQL authentifiée dans l'espace client (CWE-89) | Fuite de données personnelles et de facturation d'autres clients, exposition de hachages de mots de passe administrateurs, atteinte à la confidentialité et risque de compromission élargie. | Theoretical | Mettre à jour vers 9.0.10, 8.13.8 ou 9.1.2. Restreindre la permission View & Manage Contacts au strict nécessaire, surveiller les requêtes de l'espace client et réinitialiser les secrets exposés. | [https://thehackernews.com/2026/11/whmcs-sql-injection-flaw-could-expose.html](https://thehackernews.com/2026/11/whmcs-sql-injection-flaw-could-expose.html) |
| **CVE-2026-93700** | 9.0 | N/A | FALSE | WHMCS, versions antérieures aux correctifs 9.0.10, 8.13.8 et 9.1.2 (fonctionnalité Email Campaigns) | Traitement non sécurisé des données fournies par le client dans les campagnes e-mail, menant à la lecture de fichiers et à l'exécution de code | Lecture de secrets de configuration (identifiants de base de données), exécution de code arbitraire sur le serveur WHMCS et compromission complète de la plateforme de facturation. | Theoretical | Mettre à jour vers 9.0.10, 8.13.8 ou 9.1.2, supprimer toutes les campagnes e-mail planifiées ou en cours, vider le cache des templates, puis faire tourner les identifiants de base de données et secrets exposés. | [https://thehackernews.com/2026/11/whmcs-sql-injection-flaw-could-expose.html](https://thehackernews.com/2026/11/whmcs-sql-injection-flaw-could-expose.html) |
| **CVE-2026-109909** | 6.1 | N/A | FALSE | X.Org Server (bibliothèque libxfont, fonction BufFileRawSkip) | Lecture hors limites (CWE-125) lors de l'analyse de polices PCF, entraînant une divulgation d'informations | Divulgation d'informations sensibles en mémoire (pointeurs, données de processus), pouvant faciliter le contournement d'ASLR et l'élévation de privilèges vers root en combinaison avec une autre vulnérabilité. | Theoretical | Appliquer la mise à jour X.Org/libxfont (commit dc6c313071c8b2929b1bc165e40c8ba62737b576) via les paquets de la distribution. Restreindre l'installation de polices par les utilisateurs non privilégiés et maintenir les protections mémoire activées. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1159/](http://www.zerodayinitiative.com/advisories/ZDI-26-1159/) |
| **CVE-2026-109908** | 7.8 | N/A | FALSE | X.Org Server — bibliothèque libfontenc (parsing des fichiers d'encodage de polices) | Validation impropre d'index de tableau (CWE-129) entraînant un accès mémoire hors limites et une élévation de privilèges locale | Élévation de privilèges locale jusqu'à root sur les systèmes où X.Org Server est installé et où un attaquant peut exécuter du code non privilégié. Risque de compromission complète de l'hôte, de persistance et de mouvement latéral depuis un poste de travail ou un serveur d'applications graphiques. | None | Appliquer la mise à jour X.Org/libfontenc contenant le commit 5920c6ee144fffff84b62f5b479171f734f15316 (hxxps://gitlab[.]freedesktop[.]org/xorg/lib/libfontenc/-/commit/5920c6ee144fffff84b62f5b479171f734f15316). En attendant, limiter l'accès local aux sessions X, réduire les binaires setuid et surveiller les crashs Xorg. Aucune exploitation active n'est documentée à ce jour. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1158/](http://www.zerodayinitiative.com/advisories/ZDI-26-1158/)<br>`hxxp://www[.]zerodayinitiative[.]com/advisories/ZDI-26-1158/` |
| **CVE-2026-134068** | N/A | N/A | FALSE | Extension PostgreSQL pgactive (AWS), versions >= 2.1.0 et < 2.1.10 | Débordement de tampon sur la pile (CWE-121) dans le parsing des noms d'origine de réplication | Exécution de commandes arbitraires sur l'hôte de base de données sous l'utilisateur OS du service PostgreSQL, avec pour conséquence potentielle la compromission du cluster, l'accès aux données répliquées et un mouvement latéral vers les services AWS associés. | None | Mettre à jour vers pgactive 2.1.10 (ou version supérieure) et patcher tout code forké. Contournements : laisser pgactive.pgactive_conflict_handlers vide sur chaque nœud et empêcher les nouvelles insertions ; n'utiliser que des noms de slots/origines générés par pgactive ; sur la version 2.1.0, révoquer EXECUTE sur pgactive.pgactive_parse_replident_name pour PUBLIC. | [https://aws.amazon.com/security/security-bulletins/rss/2026-198-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-198-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-198-aws/` |
| **CVE-2026-134066** | N/A | N/A | FALSE | Graph Explorer (outil open source auto-hébergé), versions < 3.2.1 | Injection de requête (CWE-943) via des identifiants dérivés du schéma de la base graphe | Exécution de requêtes non intentionnelles avec les privilèges de Graph Explorer : lecture, modification ou suppression de données de la base graphe, contournement des contrôles d'accès applicatifs et atteinte à l'intégrité des données d'analyse. | None | Mettre à jour vers Graph Explorer 3.2.1 ou supérieur et patcher les forks. Contournement : restreindre l'accès en écriture à la base graphe connectée aux seuls principaux de confiance afin d'empêcher la création de clés ou labels piégés. | [https://aws.amazon.com/security/security-bulletins/rss/2026-199-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-199-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-199-aws/` |
| **CVE-2026-135614** | N/A | N/A | FALSE | Amazon ECS MCP Server (awslabs.ecs-mcp-server), versions < 0.1.36 | Contournement de la censure de données sensibles (CWE-200) exposant des secrets via un outil de troubleshooting | Divulgation de secrets et d'identifiants d'environnement de conteneurs ECS, pouvant mener à un accès non autorisé aux services AWS, à des ressources cloud tierces et à une compromission de la chaîne applicative. | None | Mettre à jour vers awslabs.ecs-mcp-server 0.1.36 ou supérieur (aucun contournement). Faire tourner tous les identifiants stockés en clair dans les variables d'environnement des définitions de tâches et migrer vers des références de secrets (Secrets Manager / SSM). | [https://aws.amazon.com/security/security-bulletins/rss/2026-200-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-200-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-200-aws/` |
| **CVE-2026-135414** | N/A | N/A | FALSE | Amazon OpenSearch Service — logiciel de service antérieur à R20260720 | Falsification de requête côté serveur (SSRF, CWE-918) lors de l'enregistrement d'un dépôt de snapshots | Reconnaissance et accès à des services internes depuis l'infrastructure du service managé, avec un risque de pivot vers des ressources du VPC, d'exfiltration de données ou d'interaction avec des endpoints de métadonnées cloud. | None | Mettre à jour les domaines vers le logiciel de service R20260720 ou supérieur. Contournement : limiter les porteurs du rôle manage_snapshots ainsi que les permissions es:ESHttpPut et iam:PassRole sur les domaines concernés. | [https://aws.amazon.com/security/security-bulletins/rss/2026-201-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-201-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-201-aws/` |
| **CVE-2026-123633** | 9.2 | N/A | FALSE | NGINX (open source) versions 1.19.7 à 1.30.6 et 1.31.0 à 1.31.8 ; releases NGINX Plus affectées listées par F5 | Use-after-free (CWE-416) dans la gestion des connexions HTTP/2, entraînant un déni de service et potentiellement une exécution de code | Déni de service par crash des workers NGINX sur les serveurs exposant HTTP/2 en reverse proxy ; dans des conditions particulières (ASLR désactivé ou contourné, configuration non standard), exécution de code à distance dans le contexte du worker NGINX, avec pour conséquence une compromission du reverse proxy et du trafic qu'il relaie. | Theoretical | Mettre à jour vers NGINX 1.30.7 (stable) ou 1.31.9 (mainline), ou vers un package éditeur contenant le correctif ; appliquer également le correctif de CVE-2026-123634. En attendant, désactiver HTTP/2 sur les reverse proxies exposés si possible, limiter les connexions clientes et s'assurer que l'ASLR est activée sur les hôtes. | [https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/](https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/)<br>`hxxps://unit42[.]paloaltonetworks[.]com/cve-2026-123633-nginx-http2-vulnerability/` |
| **CVE-2026-16232** | N/A | N/A | FALSE | Check Point Security Management Server avec SmartConsole | Contournement d'authentification | Vol de configurations de sécurité, de credentials et de matériel cryptographique pouvant permettre la persistance, l'évasion de contrôles et la compromission d'autres systèmes. La désactivation de politiques de sécurité expose les organisations à une perte de visibilité et de protection réseau. | Active | Appliquer les correctifs Check Point pour CVE-2026-16232, restreindre l'exposition de SmartConsole, imposer le MFA, révoquer et renouveler les credentials et certificats potentiellement compromis, auditer les politiques de sécurité et surveiller les accès administratifs. | [https://www.bleepingcomputer.com/news/security/hackers-compromise-check-point-servers-in-22-organizations/](https://www.bleepingcomputer.com/news/security/hackers-compromise-check-point-servers-in-22-organizations/) |
| **** | N/A | N/A | FALSE | Plateforme EU Academy de la Commission européenne (aucun CVE identifié dans la source) | Violation de données personnelles consécutive à une cyberattaque (aucune vulnérabilité logicielle identifiée) | Exposition de noms et d'adresses e-mail d'utilisateurs externes de la plateforme, avec un risque élevé de phishing ciblé et d'ingénierie sociale. Suspension de service pour les utilisateurs de EU Academy et atteinte à la réputation de la Commission. Aucune compromission confirmée des données du personnel à ce stade. | None | Maintenir la suspension de la plateforme jusqu'à la fin de l'investigation, notifier les utilisateurs et le CEPD, renforcer la sensibilisation au phishing, surveiller les campagnes utilisant les données exposées et durcir l'authentification des applications de formation externes. | [https://securityaffairs.com/203900/data-breach/eu-academy-users-names-and-emails-exposed-in-eu-commission-hack.html](https://securityaffairs.com/203900/data-breach/eu-academy-users-names-and-emails-exposed-in-eu-commission-hack.html) |
| **** | N/A | N/A | FALSE | National Crime Information Center (NCIC) du FBI (aucun CVE identifié dans la source) | Violation de données / intrusion non confirmée (aucune vulnérabilité logicielle identifiée) | Risque d'exposition de données judiciaires hautement sensibles (mandats, casiers, antécédents) et de perturbation des vérifications opérationnelles des forces de l'ordre. Un vol de données pourrait faciliter le doxxing d'agents, l'usurpation d'identité et le contournement de contrôles. L'impact reste à ce stade non confirmé. | None | Renforcer la surveillance des accès inter-agences, révoquer les identifiants suspects, cloisonner les interconnexions, préserver les journaux pour l'enquête et préparer un plan de continuité pour les vérifications d'antécédents en cas d'indisponibilité du système. | [https://securityaffairs.com/203865/cyber-crime/hackers-may-have-breached-fbi-database-used-by-police-nationwide.html](https://securityaffairs.com/203865/cyber-crime/hackers-may-have-breached-fbi-database-used-by-police-nationwide.html) |
| **** | 7.5 | N/A | FALSE | Oracle Autonomous AI Database (composant Oracle REST Data Services - servlet AutoUpgrade) | Injection de commande système dans un servlet (exécution de code à distance) | Exécution de code arbitraire sur le serveur hébergeant ORDS avec les droits du compte de service Oracle : accès aux données de la base, pivot vers les systèmes internes, altération de l'intégrité des données et des configurations. | Theoretical | Appliquer le correctif Oracle du CPU de novembre 2026, restreindre l'accès réseau aux endpoints ORDS et au servlet AutoUpgrade, surveiller les processus lancés par le compte de service. | [http://www.zerodayinitiative.com/advisories/ZDI-26-1149/](http://www.zerodayinitiative.com/advisories/ZDI-26-1149/) |
| **** | N/A | N/A | FALSE | laravel/framework versions 12.x antérieures à 12.73.0 et 13.x antérieures à 13.43.0 | Contournement de la politique de sécurité | Contournement des contrôles de sécurité applicatifs dans les applications Laravel non mises à jour, avec un risque d'accès non autorisé à des fonctionnalités ou données protégées. L'impact dépend des contrôles reposant sur le framework dans chaque application. | Theoretical | Mettre à jour laravel/framework vers 12.73.0 (branche 12.x) ou 13.43.0 (branche 13.x) conformément au bulletin éditeur, puis redéployer et vérifier l'intégrité applicative. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1609/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1609/)<br>[https://github.com/laravel/framework/security/advisories/GHSA-cq3g-fj94-c8p3](https://github.com/laravel/framework/security/advisories/GHSA-cq3g-fj94-c8p3) |
| **** | N/A | N/A | FALSE | Postfix versions 3.10.x < 3.10.15, 3.11.x < 3.11.8, 3.6.x < 3.6.22, 3.7.x < 3.7.24, 3.8.x < 3.8.22, 3.9.x < 3.9.16 et versions antérieures à 3.5.29 | Multiples vulnérabilités : déni de service à distance et atteinte à la confidentialité des données | Un attaquant distant peut provoquer un déni de service et porter atteinte à la confidentialité des données traitées ou stockées par le serveur Postfix. | None | Appliquer les correctifs du bulletin Postfix 3.11.8 ou les versions corrigées des branches concernées ; restreindre l'exposition SMTP ; surveiller les journaux et les redémarrages anormaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1610/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1610/) |
| **** | N/A | N/A | FALSE | Traefik versions 3.8.x < v3.8.0, 3.x < v3.7.20 et versions antérieures à v2.11.64 | Multiples vulnérabilités : déni de service à distance, atteinte à la confidentialité et contournement de la politique de sécurité | Un attaquant distant peut provoquer un déni de service, compromettre la confidentialité des données et contourner la politique de sécurité appliquée par Traefik. | None | Appliquer les correctifs des avis GHSA cités ou mettre à jour vers les versions corrigées ; restreindre l'exposition des interfaces d'administration ; surveiller les journaux et les comportements anormaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1611/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1611/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="scan-depuis-le-sous-reseau-10916032024-lun-23-nov"></div>

## Scan depuis le sous-réseau 109.160.32.0/24, (lun. 23 nov.)

### Résumé

Le diary SANS ISC du 23 novembre 2026 (handler Guy Bruneau, niveau de menace vert) documente une activité de scan provenant du sous-réseau 109.160.32.0/24. Le corps détaillé de la note n'était pas accessible lors de la collecte : le site a renvoyé une page de blocage anti-abus (adresse IP du visiteur temporairement verrouillée, contact handlers[@]dshield[.]org).

---

### Analyse opérationnelle

Un scan de sous-réseau entier constitue la phase de reconnaissance précédant généralement une tentative d'exploitation. Pour un SOC, l'enjeu est moins le scan lui-même que la corrélation avec les événements qui suivent : tentatives d'authentification, requêtes WAF anormales, exploitation de CVE récentes sur les services découverts. Les actifs ayant répondu (bannière, version applicative, page de login exposée) doivent être considérés comme prioritaires pour un durcissement immédiat. Le blocage du /24 doit être temporaire et tracé, avec une revue à échéance pour éviter une dérive de la liste de blocage.

---

### Implications stratégiques

Le scanning opportuniste et automatisé reste un bruit de fond permanent d'Internet ; il ne traduit pas nécessairement un ciblage, mais il mesure directement la qualité de la posture d'exposition d'une organisation. Les organisations dont les services exposés sont nombreux et mal identifiés subissent un risque d'exploitation accru, indépendamment de leur secteur. La tendance de fond est à la réduction de surface (décommissionnement des services inutiles, accès distants médiatisés) plutôt qu'à la seule défense périmétrique.

---

### Recommandations

* Vérifier la présence du sous-réseau 109[.]160[.]32[.]0/24 dans les logs pare-feu des 30 derniers jours et identifier les actifs ayant répondu.
* Mettre en place une alerte sur les scans multi-ports et multi-hôtes depuis une même source.
* Réduire la surface exposée : fermer les ports non nécessaires, restreindre les interfaces d'administration.
* Enrichir automatiquement les blocages avec les flux de réputation de scanners (DShield, listes publiques).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les services exposés sur Internet et maintenir un inventaire à jour des ports légitimement ouverts.
* Configurer la journalisation et la rétention des logs pare-feu/IDS/NetFlow pour permettre l'analyse rétrospective des scans.
* Définir des seuils d'alerte sur les volumes de connexions refusées par source et par destination.
* S'abonner aux flux de réputation (DShield, listes de scanners) pour enrichir automatiquement les blocages.

#### Phase 2 — Détection et analyse

* Surveiller les pics de connexions SYN vers des ports fermés ou multiples depuis une même source ou un même /24.
* Corréler les scans avec les tentatives d'authentification échouées, les erreurs 4xx/5xx applicatives et les requêtes WAF anormales.
* Rechercher dans les logs les requêtes vers des chemins d'administration exposés (VPN, RDP, SSH, portails d'authentification).
* Vérifier si le sous-réseau signalé apparaît dans les logs des 30 derniers jours et sur quels actifs.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer temporairement le sous-réseau source au niveau du pare-feu périmétrique ou du WAF, avec expiration automatique.
* Activer un rate-limiting sur les services exposés et renforcer la protection anti-bruteforce.
* Isoler ou durcir les actifs ayant répondu favorablement au scan (bannières, versions logicielles révélées).
* Notifier l'équipe réseau et consigner la mesure de blocage avec sa durée et son périmètre.

#### Phase 4 — Activités post-incident

* Revoir la pertinence du blocage après expiration et décider d'un passage en liste durable si récidive.
* Mettre à jour la base de renseignement interne avec les sources de scan récurrentes.
* Réévaluer la surface d'exposition : fermeture des services non nécessaires, migration vers des accès Zero Trust.
* Documenter l'incident et ajuster les seuils de détection si le scan est passé sous le radar.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des séquences scan → exploitation (requêtes avec payloads, tentatives d'upload, exploitation de CVE récentes) dans les 72 h suivant le scan.
* Analyser les logs de proxy et DNS pour détecter un éventuel callback sortant depuis un actif scanné.
* Comparer les ASN et plages sources avec les campagnes de scanning connues pour qualifier l'acteur.
* Extraire les user-agents et signatures de scanners pour créer des règles de détection durables.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `109[.]160[.]32[.]0/24` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595** | Active Scanning — balayage de ports et de services depuis le sous-réseau 109.160.32.0/24 |
| **T1046** | Network Service Discovery — énumération des services exposés sur Internet |

---

### Sources

* [https://isc.sans.edu/diary/rss/33550](https://isc.sans.edu/diary/rss/33550)


---

<div id="latams-financial-fraud-ecosystem-key-threats-and-strategies-for-business-protection"></div>

## LATAM’s Financial Fraud Ecosystem: Key Threats and Strategies for Business Protection

### Résumé

Article de recherche publié par ANY.RUN le 24 novembre 2026 dans la catégorie « Threat Landscape », consacré à l'écosystème de la fraude financière en Amérique latine : principales menaces observées et stratégies de protection destinées aux entreprises. Le corps détaillé de l'article n'était pas présent dans le flux collecté ; seuls le titre et la catégorie sont exploitables.

---

### Analyse opérationnelle

Le sujet impose une convergence entre les équipes SOC et les équipes de prévention de la fraude : les indicateurs utiles ne sont plus seulement techniques (domaines, hashes) mais comportementaux (vélocité transactionnelle, enrôlement d'appareil, changement de coordonnées bancaires). Les campagnes de fraude régionales s'appuient massivement sur l'ingénierie sociale (faux conseillers, smishing, faux sites marchands) et sur des malwares bancaires côté client, ce qui rend la détection côté poste de travail et côté application bancaire complémentaire. La collecte d'échantillons via sandbox reste le moyen le plus rapide d'obtenir des IOC exploitables pour le blocage.

---

### Implications stratégiques

L'Amérique latine combine forte bancarisation mobile, montée en charge des paiements instantanés et maturité hétérogène des contrôles anti-fraude : un terrain favorable à des écosystèmes criminels structurés, avec division du travail entre opérateurs de phishing, développeurs de malware, réseaux de comptes mules et blanchisseurs. Pour les institutions financières et les marchands opérant dans la région, la fraude devient un risque opérationnel et de réputation majeur, avec des exigences réglementaires croissantes en matière de notification et de remboursement. Les stratégies de protection doivent être régionalisées et partagées entre pairs plutôt que dupliquées isolément.

---

### Recommandations

* Fusionner les signaux SOC (malware, phishing) et fraude (transactions) dans une détection unifiée.
* Prioriser la surveillance des parcours d'enrôlement d'appareil et de changement de coordonnées bancaires.
* Alimenter les règles de blocage avec les IOC issus des sandboxes régionales.
* Participer aux échanges sectoriels et CERT pour anticiper les campagnes ciblant la région.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les canaux de paiement et les parcours clients exposés à la fraude (web, mobile, API bancaires).
* Définir des règles de détection de vélocité et de comportement transactionnel anormal avec les équipes fraude.
* Assurer la collecte des logs d'authentification, d'enrôlement d'appareil et de transactions pour l'analyse forensique.
* Former les équipes support et fraude aux schémas régionaux (faux conseillers, smishing, faux sites marchands).

#### Phase 2 — Détection et analyse

* Surveiller les indicateurs d'ingénierie sociale : nouveaux domaines ressemblants, campagnes SMS/messagerie, faux supports techniques.
* Détecter les anomalies d'enrôlement d'appareil et les changements de coordonnées bancaires juste avant une transaction.
* Corréler les alertes anti-fraude avec les infections malware signalées sur les postes clients (banking trojans, overlays).
* Analyser les dépôts de kits de phishing et les échantillons soumis aux sandboxes pour extraire les IOC régionaux.

#### Phase 3 — Confinement, éradication et récupération

* Geler les comptes et transactions à risque selon la procédure fraude, avec double validation humaine.
* Bloquer les domaines et numéros de téléphone identifiés au niveau des passerelles web, DNS et SMS.
* Réinitialiser les secrets d'authentification des clients compromis et révoquer les sessions actives.
* Notifier les partenaires de paiement et, si nécessaire, les autorités et l'organisme de régulation.

#### Phase 4 — Activités post-incident

* Analyser les pertes, les schémas de contournement des contrôles et les délais de détection.
* Mettre à jour les règles anti-fraude et les scénarios de sensibilisation client à partir des cas observés.
* Renforcer les contrôles sur les transactions à destination de comptes mules identifiés.
* Produire un retour d'expérience partagé avec les pairs sectoriels et les CERT nationaux.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des infrastructures de phishing ciblant la marque sur les registres de certificats et les feeds de kits.
* Traquer les familles de malware bancaire actives dans la région via les sandboxes et les feeds de partage.
* Analyser les comptes mules et les chaînes de retrait pour remonter aux opérateurs.
* Surveiller les forums et canaux de vente d'accès et de données bancaires ciblant la région.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing — vecteur d'accès initial des campagnes de fraude financière |
| **T1657** | Financial Theft — monétisation via fraude aux paiements et détournement de fonds |

---

### Sources

* [https://any.run/cybersecurity-blog/latams-financial-fraud/](https://any.run/cybersecurity-blog/latams-financial-fraud/)


---

<div id="faille-microsoft-azure-exploitee-pour-voler-les-identifiants-api-des-clients"></div>

## Faille Microsoft Azure exploitée pour voler les identifiants API des clients

### Résumé

Le 20 novembre 2026, Microsoft a commencé à notifier les tenants affectés via Azure Service Health : une vulnérabilité de l'API Microsoft Entra Connect Health a permis à des attaquants d'accéder en lecture seule à des métadonnées de tenants, dont les adresses e-mail des administrateurs et des contacts techniques. La fonctionnalité vulnérable a existé dans le service hébergé par Microsoft du 23 juillet 2026 jusqu'au déploiement d'un correctif côté service le 19 novembre 2026 (détection le 9 novembre). Aucun patch client ni mise à jour d'agent n'est requis. Les données exposées comprennent les adresses e-mail d'administration et de contact technique, les identifiants et noms de tenants, les informations de domaine, les détails de licence, le statut de synchronisation, le statut d'onboarding, les informations régionales et un certificat d'un service interne Microsoft retiré en 2024. Microsoft indique que les mots de passe, hashes de mots de passe, jetons d'authentification, clés cryptographiques actives, données d'abonnement Azure et informations d'infrastructure Active Directory n'ont pas été exposés. L'exploitation visait l'API cloud de Microsoft et ne nécessitait aucun accès aux réseaux clients ni aux infrastructures d'identité exposées sur Internet ; la version d'Entra Connect ou des agents n'a pas influencé l'exposition. Microsoft a publié un script PowerShell en lecture seule permettant de récupérer les métadonnées retournées par l'API affectée, en précisant qu'il reflète les valeurs actuelles et peut différer des données exposées si celles-ci ont changé depuis.

---

### Analyse opérationnelle

L'exposition ne relève pas d'une faille patchable côté client : la seule action possible est la détection et le durcissement. Les métadonnées obtenues constituent un matériel de reconnaissance de premier choix pour un attaquant : elles identifient nominativement les administrateurs d'identité, révèlent l'architecture d'identité hybride (synchronisation, AD FS, contrôleurs de domaine) et fournissent des adresses de contact crédibles pour des campagnes de phishing ciblé ou de fraude au président. Les fournisseurs de services managés sont particulièrement exposés, une seule compromission de leur part pouvant ouvrir l'accès à plusieurs tenants clients. Les équipes SOC doivent considérer les comptes administrateurs listés comme des cibles prioritaires et vérifier l'absence de connexions ou de réinitialisations anormales depuis le 23 juillet 2026.

---

### Implications stratégiques

Cet incident illustre un déplacement du risque vers la chaîne de confiance des fournisseurs cloud : la surface d'attaque n'est plus le logiciel installé mais l'API d'un service hébergé, hors du contrôle du client. Les organisations ne peuvent ni patcher ni vérifier directement l'exposition, ce qui renforce la dépendance à la transparence et à la réactivité des fournisseurs. Pour les MSP, l'événement soulève une question de responsabilité contractuelle et de communication vers leurs clients. Plus largement, la collecte de métadonnées d'identité — sans secret compromis — suffit à alimenter des campagnes d'ingénierie sociale à fort rendement, ce qui plaide pour une réduction drastique des coordonnées d'administration exposées et pour une authentification résistante au phishing.

---

### Recommandations

* Vérifier dans Azure Service Health si chaque tenant est concerné et exécuter le script PowerShell en lecture seule fourni par Microsoft.
* Imposer une authentification résistante au phishing (clés FIDO2, accès conditionnel strict) sur tous les comptes administrateurs d'identité.
* Réduire et cloisonner les adresses de contact administrateur/technique publiées dans les métadonnées de tenant.
* Brief er les équipes contre le phishing ciblé utilisant de faux avis de sécurité Microsoft.
* Pour les MSP : notifier les clients concernés et revoir les clauses de notification d'incident fournisseur.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les tenants Entra ID et les déploiements Entra Connect Health (serveurs de synchronisation, AD FS, contrôleurs de domaine).
* Tenir à jour la liste des contacts administrateurs et techniques exposés sur chaque tenant et la réduire au strict nécessaire.
* Vérifier la réception des notifications Azure Service Health et la diffusion interne des avis Microsoft.
* Préparer un modèle de communication et un plan de durcissement des comptes administrateurs d'identité.

#### Phase 2 — Détection et analyse

* Consulter Azure Service Health et l'historique des notifications pour identifier les tenants concernés par l'avis du 20 novembre 2026.
* Exécuter le script PowerShell en lecture seule publié par Microsoft pour récupérer les métadonnées retournées par l'API affectée.
* Rechercher des tentatives de connexion ou d'authentification inhabituelles visant les comptes administrateurs et contacts techniques exposés.
* Surveiller les campagnes de phishing ciblant les adresses d'administration d'identité et les fournisseurs de services managés.

#### Phase 3 — Confinement, éradication et récupération

* Renforcer immédiatement l'authentification des comptes administrateurs exposés (MFA résistant au phishing, accès conditionnel).
* Réduire l'exposition des adresses de contact dans les métadonnées de tenant lorsque la configuration le permet.
* Notifier les MSP et partenaires dont les coordonnées de contact ont pu être exposées.
* Bloquer les domaines d'envoi suspects identifiés dans les tentatives de phishing consécutives.

#### Phase 4 — Activités post-incident

* Documenter les données exposées par tenant (identifiants, domaines, statut de synchronisation, informations de licence).
* Revoir la gouvernance des coordonnées de contact publiées dans les services cloud et leur cycle de vie.
* Mettre à jour les procédures de veille sur les avis fournisseurs et les délais de réaction.
* Évaluer la nécessité d'une notification aux autorités ou aux clients selon les obligations applicables.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des connexions provenant d'infrastructures inhabituelles vers les portails d'administration d'identité.
* Analyser les journaux de messagerie pour détecter des leurres ciblant les administrateurs (faux avis Microsoft, fausses alertes de sécurité).
* Corréler les domaines de tenant exposés avec des campagnes de reconnaissance externes.
* Traquer les tentatives d'énumération de tenants et d'identification d'administrateurs via des services publics.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1589** |  |
| **T1598** |  |
| **T1087** |  |
| **T1528** |  |
| **T1078.004** |  |
| **T1552** | Unsecured Credentials |

---

### Sources

* [https://fieldeffect.com/blog/microsoft-entra-connect-exposure](https://fieldeffect.com/blog/microsoft-entra-connect-exposure)
* [https://www.bleepingcomputer.com/news/security/microsoft-azure-flaw-exploited-to-steal-customers-api-credentials/](https://www.bleepingcomputer.com/news/security/microsoft-azure-flaw-exploited-to-steal-customers-api-credentials/)


---

<div id="sunspotsvoicescom-par-inc-ransom"></div>

## sunspotsvoices.com par inc ransom

### Résumé

Entrée de la plateforme RansomLook datée du 24 novembre 2026 référençant le domaine sunspotsvoices[.]com comme victime revendiquée par le groupe ransomware Inc Ransom. La fiche affiche un statut « 5/13 degraded » pour le groupe. Aucun détail supplémentaire (secteur, volume de données, échéance) n'était disponible dans le flux collecté.

---

### Analyse opérationnelle

Une revendication sur un site de fuite signale en général une exfiltration préalable : la priorité pour une équipe SOC n'est pas le chiffrement mais la recherche d'une exfiltration de données et d'une persistance résiduelle. Les groupes de type Inc Ransom pratiquent l'extorsion double, avec publication d'échantillons de données en cas de non-paiement. La vérification doit porter sur les journaux d'accès distants, les créations de comptes, les transferts volumétriques sortants et les journaux des serveurs de fichiers et de sauvegarde. Le statut « degraded » du groupe peut indiquer une perturbation de son infrastructure, sans réduire la menace opérationnelle.

---

### Implications stratégiques

La publication d'une victime sur un site de fuite a des conséquences bien au-delà de l'IT : notification réglementaire, risque de contentieux, atteinte à la réputation et perte de confiance des clients et partenaires. La fragmentation des groupes ransomware (scissions, statuts instables, affiliates mobiles) rend l'attribution difficile mais ne change pas les mesures de défense. Les organisations doivent considérer la surveillance des sites de fuite comme un canal de détection à part entière, complémentaire de la télémétrie interne.

---

### Recommandations

* Vérifier si l'organisation, ses filiales ou ses partenaires apparaissent sur les sites de fuite surveillés.
* Contrôler l'exposition des accès distants (VPN, RDP) et imposer le MFA partout.
* Tester la restaurabilité des sauvegardes et leur isolation du réseau de production.
* Préparer à l'avance les obligations de notification et la communication de crise en cas de fuite avérée.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Surveiller les sites de fuite et agrégateurs (RansomLook, ranwatch) pour détecter toute mention de l'organisation ou de ses partenaires.
* Tenir à jour un plan de réponse ransomware incluant la communication de crise et les obligations de notification.
* Vérifier l'isolation des sauvegardes, la segmentation réseau et la couverture EDR des serveurs critiques.
* Préparer un inventaire des données sensibles et de leur localisation pour évaluer rapidement l'impact d'une fuite.

#### Phase 2 — Détection et analyse

* Rechercher le nom de domaine de l'organisation et de ses filiales dans les publications des groupes ransomware.
* Surveiller les signaux précurseurs : accès RDP/VPN anormaux, exfiltration volumétrique, création de comptes, désactivation d'antivirus.
* Analyser les alertes EDR sur les techniques de chiffrement massif et de suppression des clichés instantanés.
* Corréler les accès sortants inhabituels vers des services de stockage ou de transfert de fichiers.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments compromis et révoquer les comptes à privilèges suspectés.
* Couper les accès distants (VPN, RDP) et invalider les sessions actives.
* Préserver les preuves (images mémoire, journaux) avant toute remédiation destructive.
* Activer la cellule de crise et préparer la communication externe en coordination avec le conseil juridique.

#### Phase 4 — Activités post-incident

* Analyser le vecteur d'intrusion initial et le temps de présence de l'attaquant.
* Évaluer le périmètre exact des données exfiltrées et les obligations de notification (RGPD, autorités sectorielles).
* Reconstruire les systèmes depuis des sauvegardes saines et durcir les accès à privilèges.
* Tirer un retour d'expérience sur les délais de détection et la couverture des contrôles.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les TTP et IOC associés à Inc Ransom dans les journaux historiques (accès initiaux, outils de transfert, comptes créés).
* Analyser les connexions vers les infrastructures de l'acteur et les domaines de fuite associés.
* Vérifier la présence de données de l'organisation dans les échantillons publiés par le groupe.
* Traquer les mécanismes de persistance et les mouvements latéraux sur les serveurs de fichiers et de sauvegarde.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `sunspotsvoices[.]com` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact — opérations de chiffrement/extorsion caractéristiques des groupes ransomware |
| **T1657** | Financial Theft — monétisation par extorsion et revente de données |

---

### Sources

* [https://www.ransomlook.io//group/inc%20ransom](https://www.ransomlook.io//group/inc%20ransom)


---

<div id="possible-phishing-on-hxxpstiendaairisesjsde-analysis-at-httpsurldnaioscan6b05bc4d3b775000076a72d6-cybersecurity-phishing-infosec-urldna-scam-infosec"></div>

## Possible Phishing 🎣  on: ⚠️hxxps[:]//tienda[.]airis[.]es/js/de  🧬 Analysis at: https://urldna.io/scan/6b05bc4d3b775000076a72d6 #cybersecurity #phishing #infosec #urldna #scam #infosec

### Résumé

Analyse urlDNA du 24 novembre 2026 (16:33 UTC) classant comme « potentiellement malveillante » l'URL hxxps://tienda[.]airis[.]es/js/de. La page affichée usurpe la marque DPD (« Zahlung bestätigen - Schweizerische DPD ») et demande le paiement de 2,99 EUR pour débloquer une livraison, avec un formulaire de saisie de carte bancaire (nom complet, numéro de carte, vérification). La page est hébergée sur 217[.]160[.]0[.]250 (AS8560, IONOS SE, Essen, Allemagne) et redirige vers hxxps://rizarichempire[.]com/UP20100253652CH/index[.]php. Le certificat présenté pour tienda[.]airis[.]es est expiré (validité 2021-2022). La page est classée dans les catégories Phishing, Package Delivery, Payment Fraud et Credential Harvesting.

---

### Analyse opérationnelle

Le schéma est classique et à faible coût : un petit montant (2,99 EUR) réduit la vigilance de la victime, et la saisie de données de carte permet une fraude immédiate ou une revente. Le fait que l'URL soit hébergée sur un domaine légitime compromis (tienda[.]airis[.]es) plutôt que sur un domaine ressemblant complique la détection par réputation de domaine : le blocage doit porter sur le chemin complet et sur le domaine de destination finale. Les équipes SOC doivent prioriser le blocage de rizarichempire[.]com et la recherche de requêtes vers le chemin /js/de sur les proxies. Les victimes ayant saisi leurs données doivent faire l'objet d'une procédure d'opposition carte et de surveillance transactionnelle.

---

### Implications stratégiques

L'usurpation de marques logistiques reste l'un des vecteurs de phishing les plus rentables car elle touche un très large public, indépendamment du secteur d'activité de la victime. La compromission de sites légitimes pour y héberger des pages de phishing constitue une tendance durable qui érode la confiance dans les domaines de marque établis. Pour les acteurs de la logistique et du e-commerce, la protection de la marque devient un enjeu de sécurité opérationnelle : surveillance des typosquats, des pages hébergées illicitement et des campagnes SMS. Les autorités et les CERT encouragent le signalement rapide pour accélérer les takedowns.

---

### Recommandations

* Bloquer rizarichempire[.]com, l'URL tienda[.]airis[.]es/js/de et l'IP 217[.]160[.]0[.]250 sur proxy, DNS et messagerie.
* Sensibiliser les utilisateurs : aucun transporteur ne demande de données de carte pour un complément de quelques euros.
* Mettre en place une surveillance des pages usurpant les marques logistiques et des certificats expirés sur des domaines de marque.
* Traiter les signalements utilisateurs en moins d'une heure et lancer les demandes de takedown.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer le blocage des URL et domaines malveillants au niveau du proxy, du DNS et de la messagerie.
* Sensibiliser les utilisateurs aux faux avis de livraison et de paiement de frais de transport.
* Mettre en place une boîte de signalement de phishing et un processus de tri rapide.
* Vérifier la couverture EDR des postes mobiles et des navigateurs utilisés pour les achats en ligne.

#### Phase 2 — Détection et analyse

* Détecter les e-mails et SMS contenant des liens vers des domaines usurpant des marques logistiques.
* Surveiller les requêtes DNS/proxy vers tienda[.]airis[.]es et rizarichempire[.]com.
* Rechercher les soumissions d'URL suspectes dans les outils de sandbox et les feeds de réputation.
* Analyser les signalements utilisateurs mentionnant un paiement de petits montants pour une livraison.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les URL, domaines et l'adresse IP identifiés sur l'ensemble des points de contrôle.
* Faire supprimer ou neutraliser les messages de phishing dans les boîtes des destinataires.
* Pour les utilisateurs ayant saisi leurs données : opposition carte, réinitialisation des identifiants, surveillance transactionnelle.
* Signaler l'URL au service de sandbox et aux registrars/hébergeurs pour takedown.

#### Phase 4 — Activités post-incident

* Recenser les victimes et les pertes, documenter les données de carte exposées.
* Mettre à jour les règles de détection et les scénarios de sensibilisation à partir du kit observé.
* Suivre la réapparition du kit sur d'autres domaines ou hébergements.
* Communiquer auprès des utilisateurs sur le schéma d'arnaque identifié.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres URL utilisant le même modèle de chemin (/js/de) ou la même infrastructure (AS8560, IONOS).
* Traquer les certificats et enregistrements DNS récents liés à des marques logistiques usurpées.
* Analyser les journaux de proxy pour identifier d'autres victimes potentielles du kit.
* Corréler avec les campagnes de smishing signalées sur la même période.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://tienda[.]airis[.]es/js/de` | Medium |
| URL | `hxxps://rizarichempire[.]com/UP20100253652CH/index[.]php` | Medium |
| IP | `217[.]160[.]0[.]250` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link — lien menant vers une page de phishing usurpant DPD |
| **T1204** | User Execution — saisie des données de carte par la victime sur la page frauduleuse |
| **T1657** | Financial Theft — captation des données de paiement (2,99 EUR) et fraude à la carte |

---

### Sources

* [https://urldna.io/scan/6b05bc4d3b775000076a72d6](https://urldna.io/scan/6b05bc4d3b775000076a72d6)
* [https://infosec.exchange/@urldna/117674017457228465](https://infosec.exchange/@urldna/117674017457228465)


---

<div id="openai-et-cisco-devoilent-shirudo-pour-bloquer-les-exploits-avant-les-correctifs"></div>

## OpenAI et Cisco dévoilent Shirudo pour bloquer les exploits avant les correctifs

### Résumé

OpenAI et Cisco ont publié Shirudo, une approche open source (licence BSD 2-Clause) qui génère des « boucliers » destinés à bloquer l'exploitation d'une vulnérabilité pendant que les équipes déploient le correctif définitif. Shirudo fonctionne sur Linux et s'appuie sur eBPF pour intercepter les entrées malveillantes au niveau du noyau. Un agent IA identifie le point d'interception, écrit le code du bouclier, le teste puis le déploie sans arrêter le système. OpenAI indique avoir testé Shirudo sur la vulnérabilité Java4Shell avec des agents Codex : le bouclier a rejeté les entrées malveillantes dirigées vers Elasticsearch tout en maintenant la plateforme opérationnelle. Les deux entreprises invitent la communauté à contribuer et souhaitent rendre les boucliers testés disponibles en parallèle des divulgations de vulnérabilités. Le contexte est celui d'une découverte accélérée de vulnérabilités par les modèles d'IA, qui réduit les délais de correction disponibles pour les équipes.

---

### Analyse opérationnelle

Shirudo répond à un problème concret : l'écart entre la divulgation d'une CVE et la capacité à patcher l'ensemble du parc. Pour un SOC, un bouclier eBPF déployé sur un serveur Linux exposé peut réduire la fenêtre d'exposition sans redémarrage, à condition d'être validé en environnement de test pour éviter les faux positifs et l'impact sur les performances. Le bouclier ne remplace ni le correctif définitif ni les contrôles réseau : il s'agit d'un correctif virtuel temporaire, qui doit être tracé, daté et retiré après application du patch. La dépendance à un agent IA pour générer le code d'interception impose une revue humaine du code produit avant tout déploiement en production.

---

### Implications stratégiques

L'arrivée de modèles d'IA capables de découvrir des vulnérabilités inédites modifie l'équation économique de la gestion des vulnérabilités : les délais de correction deviennent le facteur limitant, et non plus la détection. La réponse passe par des mécanismes d'atténuation temporaire industrialisés, portés par des acteurs de premier plan et ouverts à la communauté. Pour les organisations, cela crée une nouvelle dépendance à l'écosystème open source et à la qualité des boucliers publiés, avec des enjeux de confiance, de support et de responsabilité. Le secteur de la santé, cité dans l'article, illustre les environnements où les systèmes ne peuvent pas être patchés rapidement et où les correctifs virtuels ont une valeur opérationnelle immédiate.

---

### Recommandations

* Évaluer Shirudo dans un environnement de test avant tout déploiement sur des systèmes Linux exposés.
* Formaliser une procédure de correctif virtuel : validation, déploiement, traçabilité, retrait après patch.
* Maintenir une revue humaine du code généré par l'agent IA avant mise en production.
* Ne pas relâcher les contrôles réseau et la segmentation au motif qu'un bouclier est actif.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Évaluer la pertinence d'un correctif virtuel eBPF sur les systèmes Linux critiques exposés à des CVE non corrigées.
* Mettre en place un environnement de test isolé pour valider les boucliers avant déploiement en production.
* Documenter les procédures de déploiement et de retrait des correctifs virtuels, avec plan de retour arrière.
* Vérifier la compatibilité des noyaux et la présence des prérequis eBPF sur le parc Linux.

#### Phase 2 — Détection et analyse

* Surveiller les tentatives d'exploitation bloquées par le bouclier et les alertes associées.
* Corréler les événements du bouclier avec les journaux applicatifs pour détecter des contournements.
* Vérifier que le bouclier n'occasionne pas de faux positifs sur les requêtes légitimes.
* Suivre les avis de vulnérabilité et les boucliers publiés par la communauté.

#### Phase 3 — Confinement, éradication et récupération

* Déployer le bouclier sur les actifs exposés en attendant le correctif définitif.
* Maintenir la segmentation réseau et les contrôles d'accès en complément du bouclier.
* En cas de défaillance du bouclier, isoler l'actif concerné et appliquer une mesure de contournement manuelle.
* Consigner chaque déploiement de bouclier avec sa CVE associée et sa date d'expiration prévue.

#### Phase 4 — Activités post-incident

* Appliquer le correctif définitif dès sa disponibilité et retirer le bouclier temporaire.
* Évaluer l'efficacité du bouclier (attaques bloquées, faux positifs, impact performance).
* Mettre à jour la politique de gestion des vulnérabilités pour intégrer les correctifs virtuels.
* Contribuer ou suivre les retours de la communauté open source sur les boucliers utilisés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des tentatives d'exploitation antérieures au déploiement du bouclier sur les actifs concernés.
* Analyser les journaux noyau et applicatifs pour détecter des comportements post-exploitation.
* Traquer les indicateurs d'exploitation de la CVE concernée (payloads, chaînes de requêtes).
* Vérifier l'absence de persistance installée avant la mise en place du bouclier.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application — cas d'usage ciblé par les boucliers Shirudo |
| **T1203** | Exploitation for Client Execution — atténuation des tentatives d'exploitation en attendant le correctif |

---

### Sources

* [https://www.healthcareinfosecurity.com/openai-cisco-unveil-shirudo-to-block-exploits-before-patches-a-33511](https://www.healthcareinfosecurity.com/openai-cisco-unveil-shirudo-to-block-exploits-before-patches-a-33511)


---

<div id="copperstone-clothing-company-fabricantexportateur-indien-de-vetements-parc-erp-sql-server-par-pixelleaks"></div>

## Copperstone Clothing Company (fabricant/exportateur indien de vêtements, parc ERP SQL Server) par pixelleaks

### Résumé

Le groupe de rançongiciel Pixelleaks a inscrit Copperstone Clothing Company, fabricant et exportateur indien de vêtements, sur sa plateforme de publication de victimes. La fiche victime précise que l'environnement concerné repose sur un ERP hébergé sur SQL Server. La source ne fournit ni volume de données exfiltrées, ni date d'intrusion, ni montant de rançon, ni échantillon de preuve.

---

### Analyse opérationnelle

L'intérêt opérationnel réside dans la cible : un ERP sur SQL Server, socle très répandu dans l'industrie textile, souvent exposé via des portails applicatifs ou des comptes de service faiblement protégés. Les équipes SOC doivent considérer la publication comme un indicateur d'exfiltration déjà réalisée (double extorsion) et non comme un simple chiffrement. Priorités : inventaire des instances SQL accessibles depuis Internet, revue des droits des comptes de service, contrôle des exports de bases et des sauvegardes, surveillance des connexions sortantes volumineuses. En l'absence d'IOC publiés, la détection doit être comportementale (accès massif aux tables, BACKUP vers des chemins inhabituels, usage de xp_cmdshell).

---

### Implications stratégiques

Les sous-traitants et exportateurs du textile constituent une cible de choix : données commerciales sensibles (clients, prix, plans de collection), dépendance à un ERP unique et maturité sécurité souvent inégale. Une fuite peut entraîner la perte de contrats avec des donneurs d'ordre occidentaux imposant des exigences de sécurité dans la chaîne d'approvisionnement, ainsi que des obligations de notification au titre du DPDP Act indien et du RGPD pour les données de clients européens. La multiplication des listings Pixelleaks illustre la fragmentation du marché des rançongiciels vers des groupes de niche ciblant les PME industrielles.

---

### Recommandations

* Recenser et fermer toute exposition Internet directe des instances SQL Server et des portails ERP.
* Imposer le MFA sur les accès distants (VPN, RDP, portails) et segmenter les bases de données du réseau bureautique.
* Mettre en place des sauvegardes hors ligne immuables et tester trimestriellement la restauration de l'ERP.
* Surveiller en continu les plateformes de fuite et les flux de renseignement pour détecter les listings précoces.
* Réduire les privilèges des comptes de service SQL et faire tourner leurs secrets.
* Préparer un plan de notification de violation de données couvrant clients européens et autorités indiennes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier l'exposition Internet des instances SQL Server et des portails ERP (ports 1433/443, VPN, RDP) et vérifier l'absence d'accès direct depuis l'extérieur.
* Valider l'existence de sauvegardes hors ligne immuables (3-2-1) pour les bases ERP et tester une restauration complète.
* Définir un plan de communication de crise incluant les obligations de notification (clients, autorités, CNIL/équivalent indien DPDP Act) en cas de fuite de données personnelles.
* Recenser les comptes de service SQL, les comptes à privilèges et appliquer le moindre privilège + rotation des secrets.

#### Phase 2 — Détection et analyse

* Surveiller la plateforme de fuite Pixelleaks et les flux de renseignement pour détecter l'apparition de la victime et d'éventuels échantillons publiés.
* Rechercher des connexions SQL anormales (authentification en force, requêtes en masse, xp_cmdshell, BACKUP DATABASE vers un chemin inhabituel).
* Analyser les journaux d'accès VPN/RDP et les créations de comptes ou de tâches planifiées non autorisées sur les serveurs ERP.
* Détecter les pics d'exfiltration sortante (volume, destination inconnue) via proxy/pare-feu et la présence d'archives compressées non planifiées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les serveurs ERP/SQL compromis du réseau et révoquer les sessions et comptes de service suspectés.
* Bloquer les IOC de l'infrastructure de l'attaquant (IP, domaines) au niveau pare-feu, proxy et DNS.
* Réinitialiser l'ensemble des identifiants à privilèges (domaine, SQL, sauvegarde) et activer le MFA sur les accès distants.
* Préserver les preuves (images disque, journaux, mémoire) avant toute remédiation et engager un prestataire de réponse à incident.

#### Phase 4 — Activités post-incident

* Reconstruire les systèmes impactés depuis des sauvegardes saines et vérifier l'intégrité des données ERP restaurées.
* Conduire une analyse post-mortem (vecteur initial, dwell time, données exfiltrées) et publier un rapport de retour d'expérience.
* Renforcer la segmentation entre le réseau bureautique, les serveurs de bases de données et les systèmes de production industrielle.
* Mettre à jour les procédures de notification et la communication vers les clients/partenaires si des données les concernant ont fuité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts de l'outillage Pixelleaks et de ses affiliés (binaires de chiffrement, notes de rançon, scripts de suppression de journaux).
* Chasser les mouvements latéraux via SMB/WMI/WinRM et les accès aux partages contenant des exports de bases.
* Vérifier la présence de comptes créés hors procédure et de clés SSH/API ajoutées récemment.
* Corréler les indicateurs de la plateforme Pixelleaks avec les journaux historiques sur 90 jours.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Données chiffrées pour impact (rançongiciel) |
| **T1657** | Extorsion financière via la plateforme de fuite (double extorsion) |
| **T1567** | Exfiltration de données vers un service externe / publication sur site de fuite |

---

### Sources

* [https://www.ransomlook.io//group/pixelleaks](https://www.ransomlook.io//group/pixelleaks)


---

<div id="webworm-un-apt-despionnage-aligne-sur-la-chine-a-reconstruit-softether-vpn-a-partir-du-code-source-et-lutilise-comme-backdoor-personnalisee"></div>

## Webworm, un APT d'espionnage aligné sur la Chine, a reconstruit SoftEther VPN à partir du code source et l'utilise comme backdoor personnalisée

### Résumé

Rapid7 a publié le 19 novembre une recherche sur un outil personnalisé dérivé de SoftEther VPN Bridge, compilé pour Windows x64 et désigné en interne « NtMonitor », attribué au groupe APT Webworm avec une confiance modérée. Webworm, aligné sur la Chine et actif depuis au moins 2017, cible principalement des organisations gouvernementales, avec un accent sur l'Europe, et est également suivi sous les noms Erudite Mogwai et Space Pirates. Les attaquants ont modifié les métadonnées et le branding interne en « Network Monitor Software », renommé les bannières de débogage, noms de services, clés de registre et règles de pare-feu en « NtMonitor VPN » (de manière inconsistante), renommé les endpoints HTTP du protocole VPN, modifié le watermark de handshake pour contourner les signatures SoftEther standard, extrait et embarqué le fichier hamcore.se2 dans l'exécutable, et renommé puis chiffré le fichier de configuration en clair avec un chiffrement maison. L'attribution s'appuie sur l'alignement avec les TTP connus de Webworm et sur des adresses IP reliées à son infrastructure historique. Le blog Rapid7 contient des IOC et des règles YARA. Le vecteur d'accès initial privilégié serait l'exploitation de vulnérabilités d'applications web exposées, avec un attrait marqué du groupe pour le scanner Nuclei.

---

### Analyse opérationnelle

La valeur de cette recherche est défensive : l'attaquant a méthodiquement neutralisé la surface de détection de SoftEther (artefacts de build, chaînes, endpoints, watermark de handshake, configuration en clair). Les signatures existantes basées sur les noms de services, les chemins ou les empreintes de fichiers deviennent inefficaces. Les équipes SOC doivent basculer vers une détection comportementale : apparition d'adaptateurs réseau virtuels, tunnels sortants persistants vers des IP inconnues, services Windows non catalogués, exécutables embarquant des ressources compressées. Le contrôle d'égression est la contre-mesure la plus rentable, car le composant VPN Bridge a précisément pour fonction de relier le réseau victime à un serveur attaquant. Côté surface d'attaque, la priorité reste le patching des applications web exposées et le durcissement WAF, cohérents avec l'usage de Nuclei.

---

### Implications stratégiques

Cette campagne confirme la tendance des APT alignés sur la Chine à troquer les implants sur mesure contre la personnalisation d'outils open source légitimes, ce qui réduit le coût de développement et brouille l'attribution. L'accent mis sur l'Europe et les organisations gouvernementales en fait un risque direct pour les ministères, collectivités et opérateurs d'importance vitale, avec un enjeu de souveraineté sur les données et les communications internes. La persistance longue durée via tunnel VPN permet de l'exfiltration progressive et discrète, difficile à distinguer du trafic légitime. Pour les décideurs, cela plaide pour des investissements dans la détection comportementale réseau, la maîtrise de l'égression et la réduction de la surface exposée plutôt que dans l'empilement de signatures.

---

### Recommandations

* Déployer les règles YARA et IOC publiés par Rapid7 et les intégrer aux chaînes de détection existantes.
* Mettre en œuvre un contrôle d'égression deny-by-default sur les segments gouvernementaux sensibles.
* Interdire par politique applicative les clients VPN non approuvés et surveiller l'installation d'adaptateurs TAP.
* Prioriser le patching des applications web exposées et le durcissement WAF face à l'usage de Nuclei.
* Chasser les artefacts « NtMonitor » dans les services, le registre et les règles de pare-feu.
* Partager les indicateurs avec les CERT nationaux et les pairs sectoriels.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Interdire ou encadrer strictement l'usage de clients VPN non approuvés (SoftEther, OpenVPN portable, tunnels SSH) par politique applicative et EDR.
* Mettre en place une liste blanche d'applications et une surveillance des services Windows créés hors catalogue logiciel.
* Cartographier les applications web exposées sur Internet et planifier leur patching mensuel ainsi que le durcissement WAF.
* Déployer des règles YARA et des signatures comportementales sur les binaires signés/non signés se présentant comme des outils de supervision réseau.

#### Phase 2 — Détection et analyse

* Rechercher les artefacts nommés « NtMonitor », « NtMonitor VPN » ou « Network Monitor Software » dans les services, clés de registre, règles de pare-feu et bannières de débogage.
* Détecter les connexions sortantes persistantes vers des IP externes sur des ports VPN non standards, notamment depuis des serveurs gouvernementaux.
* Surveiller la création de services Windows et l'installation de pilotes réseau virtuels (adaptateurs TAP) non planifiés.
* Analyser les journaux d'applications web exposées à la recherche de tentatives d'exploitation et de scans (user-agents Nuclei, requêtes template).

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes hébergeant le tunnel et bloquer en sortie les destinations identifiées comme infrastructure Webworm.
* Appliquer un contrôle d'égression strict (deny-by-default) sur les segments sensibles pour empêcher la reconnexion du tunnel.
* Révoquer les identifiants présents sur les systèmes compromis et reconstruire les machines plutôt que les nettoyer.
* Conserver les binaires et configurations chiffrées pour analyse forensique avant suppression.

#### Phase 4 — Activités post-incident

* Auditer l'ensemble du parc pour d'autres builds modifiés de SoftEther et pour des accès persistants résiduels.
* Revoir la posture de patching des applications web exposées et intégrer les résultats au registre des risques.
* Partager les IOC et règles YARA avec les CERT sectoriels et les pairs gouvernementaux.
* Renforcer la détection comportementale plutôt que la détection par empreinte, l'attaquant ayant supprimé les artefacts de build.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les fichiers hamcore.se2 embarqués dans des exécutables et les configurations VPN chiffrées avec un algorithme non standard.
* Rechercher les renommages d'endpoints HTTP du protocole VPN et les watermarks de handshake modifiés dans les journaux réseau.
* Corréler les IP de sortie avec l'infrastructure Webworm historiquement documentée.
* Examiner les journaux de scan web sur 90 jours pour identifier une reconnaissance préalable via Nuclei.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1572** | Tunnellisation de protocole via un client SoftEther VPN Bridge modifié |
| **T1036** | Masquage : renommage du binaire et des artefacts en « NtMonitor » / « Network Monitor Software » |
| **T1027** | Obfuscation : suppression des artefacts de build, chiffrement du fichier de configuration |
| **T1090** | Proxy / relais via le composant VPN Bridge reliant le réseau victime à l'infrastructure attaquante |
| **T1190** | Exploitation d'applications web exposées sur Internet comme vecteur d'accès initial |
| **T1595** | Scan actif des surfaces exposées (usage de Nuclei) |

---

### Sources

* [https://www.darkreading.com/perimeter/webworm-slithers-customized-softether-vpn](https://www.darkreading.com/perimeter/webworm-slithers-customized-softether-vpn)


---

<div id="fastunlock-une-vulnerabilite-zero-day-non-corrigee-de-windows-11-transforme-narrator-en-un-moyen-de-passer-outre-lecran-de-verrouillage"></div>

## FastUnlock : une vulnérabilité zero-day non corrigée de Windows 11 transforme Narrator en un moyen de passer outre l'écran de verrouillage

### Résumé

Une faille Windows 11 non corrigée, baptisée FastUnlock et rendue publique, permettrait de contourner l'écran de verrouillage en détournant la fonctionnalité d'accessibilité Narrator. Selon la source, un attaquant disposant d'un accès physique au poste pourrait franchir le verrouillage sur une large part des appareils, remettant en cause l'hypothèse selon laquelle un portable verrouillé et chiffré par BitLocker protège les données en cas de perte, de vol ou d'absence. La source ne précise ni identifiant CVE, ni version exacte affectée, ni statut de correctif éditeur dans l'extrait disponible.

---

### Analyse opérationnelle

Le scénario d'attaque est physique et court-circuite deux contrôles habituellement considérés comme suffisants : l'écran de verrouillage et le chiffrement de volume. Les organisations doivent réévaluer leur modèle de menace pour les postes nomades, les salles de réunion, les espaces de coworking et les flottes de terrain. Les mesures immédiates sont la désactivation des fonctionnalités d'accessibilité depuis l'écran de verrouillage par GPO/Intune, l'activation d'une authentification pré-démarrage BitLocker (PIN ou clé USB) en complément du TPM, la réduction du délai de verrouillage automatique et la surveillance des journaux BitLocker et d'ouverture de session. En l'absence de correctif, la compensation passe par la politique de configuration, pas par la détection.

---

### Implications stratégiques

Cette vulnérabilité fragilise les engagements de conformité fondés sur le chiffrement au repos : un vol de portable peut devenir une violation de données notifiable. Les secteurs à forte mobilité (santé, conseil, services financiers, administrations décentralisées) sont les plus exposés, ainsi que les organisations pratiquant le BYOD ou le télétravail intensif. Au-delà du cas technique, elle illustre la persistance des angles morts liés à l'accès physique dans des programmes de sécurité largement orientés vers les menaces réseau, et devrait alimenter la révision des politiques de protection de l'information et des assurances cyber.

---

### Recommandations

* Désactiver l'accès à Narrator et aux autres options d'accessibilité depuis l'écran de verrouillage via GPO/Intune.
* Imposer une authentification pré-démarrage BitLocker (PIN ou clé USB) sur les postes nomades sensibles.
* Réduire le délai de verrouillage automatique et interdire la mise en veille sans verrouillage.
* Surveiller les journaux BitLocker et les événements d'ouverture de session pour détecter les anomalies.
* Suivre la publication du correctif Microsoft et le déployer en priorité sur les flottes nomades.
* Sensibiliser les utilisateurs au risque physique et intégrer ce scénario aux exercices de réponse à incident.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Réévaluer la menace physique dans la politique de sécurité : un portable verrouillé et chiffré n'est pas un portable sûr.
* Imposer une authentification pré-démarrage (BitLocker avec PIN ou clé USB) plutôt que TPM seul sur les postes nomades sensibles.
* Désactiver ou restreindre les fonctionnalités d'accessibilité accessibles depuis l'écran de verrouillage (Narrator, loupe, clavier visuel) via GPO/Intune.
* Former les utilisateurs au risque de laisser un poste déverrouillé ou en veille dans un espace partagé.

#### Phase 2 — Détection et analyse

* Surveiller les événements de déverrouillage anormaux et les séquences d'activation de Narrator depuis l'écran de verrouillage.
* Détecter les tentatives répétées de déverrouillage échouées suivies d'une ouverture de session réussie sur un même poste.
* Contrôler les journaux BitLocker (déverrouillage, changement de protecteurs) et alerter sur toute modification.
* Corréler avec les données d'accès physique (badges, caméras) pour les zones sensibles.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement tout poste suspecté d'avoir été déverrouillé par contournement et révoquer ses sessions et jetons.
* Forcer la rotation des secrets stockés localement (identifiants en cache, cookies de session, clés DPAPI).
* Appliquer les mesures d'atténuation disponibles (désactivation de Narrator au verrouillage, PIN pré-démarrage) sur l'ensemble du parc.
* Suspendre l'usage nomade des modèles non protégés jusqu'à publication d'un correctif éditeur.

#### Phase 4 — Activités post-incident

* Suivre la publication du correctif Microsoft et planifier son déploiement prioritaire sur les postes nomades.
* Mettre à jour la politique de chiffrement et de verrouillage (délai de verrouillage, authentification pré-démarrage, restrictions d'accessibilité).
* Documenter l'incident et évaluer l'exposition réelle des données (accès aux partages, applications métier, messagerie).
* Intégrer le scénario « accès physique » aux exercices de réponse à incident.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les traces d'utilisation de Narrator ou d'outils d'accessibilité hors contexte d'usage légitime.
* Examiner les journaux d'ouverture de session sur les postes nomades pour des connexions hors horaires ou depuis des lieux inhabituels.
* Vérifier l'état des protecteurs BitLocker sur l'ensemble du parc et identifier les postes en TPM seul.
* Contrôler l'absence de comptes locaux créés ou de mots de passe modifiés après un déverrouillage suspect.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1548** |  |
| **T1562.001** |  |

---

### Sources

* [https://insomnisec.com/posts/2026-11-24-fastunlock-windows-narrator-lock-screen-bypass_insomnisec_v1/](https://insomnisec.com/posts/2026-11-24-fastunlock-windows-narrator-lock-screen-bypass_insomnisec_v1/)
* [https://cyberveille.curated.co/issues/585](https://cyberveille.curated.co/issues/585)
* [https://mastodon.social/@cyberveille/117670381637660242](https://mastodon.social/@cyberveille/117670381637660242)


---

<div id="impossible-de-cross-poster-une-video-twitter-vers-telegram-mais-la-cia-enquete-aujourdhui-sur-une-compromission"></div>

## Impossible de cross-poster une vidéo Twitter vers Telegram, mais la CIA enquête aujourd'hui sur une compromission.

### Résumé

Un message publié sur le canal Telegram vxunderground affirme, sans fournir de preuve ni de détail technique, que plusieurs entités gouvernementales américaines auraient été compromises : USDA, CIA et FBI (à deux reprises), avec des indisponibilités alléguées de NSANet et de la FAA. Le message est rédigé sur un ton sarcastique et ne contient aucun indicateur, aucune chronologie ni aucune source vérifiable. Aucune corroboration officielle n'est disponible dans le flux.

---

### Analyse opérationnelle

Il s'agit d'une allégation non corroborée relevant du bruit informationnel. Elle ne doit pas déclencher de réponse à incident mais peut servir de signal de veille : si des compromissions réelles existaient, les équipes défensives d'organisations partenaires ou partageant des infrastructures pourraient observer des effets de bord (réutilisation d'identifiants, accès tiers, indisponibilité de services fédérés). La conduite à tenir est de vérifier auprès des canaux officiels, de surveiller ses propres journaux d'authentification et d'accès aux services gouvernementaux, et de ne pas relayer l'information. Aucun IOC exploitable n'est fourni.

---

### Implications stratégiques

La diffusion d'allégations de compromission d'agences fédérales sur des canaux à forte audience illustre la porosité entre veille cyber et guerre informationnelle : la rumeur elle-même devient un vecteur d'influence et d'incertitude. Pour les décideurs, l'enjeu est de disposer d'un processus de qualification rapide des sources afin d'éviter les décisions précipitées (gel de services, communications alarmistes) tout en conservant la capacité à réagir si la menace se confirme. Ce type d'épisode renforce la nécessité de canaux de partage d'information formels et authentifiés avec les autorités.

---

### Recommandations

* Ne pas relayer l'allégation avant corroboration par une source officielle.
* Vérifier auprès des CERT et canaux gouvernementaux officiels l'existence d'avis ou de confirmations.
* Surveiller ses propres journaux d'authentification et d'accès aux services fédérés pour détecter des effets de bord.
* Formaliser une procédure de qualification des rumeurs issues des réseaux sociaux et de Telegram.
* Documenter la source et l'horodatage de l'allégation à des fins d'analyse ultérieure.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Établir une procédure de qualification des rumeurs de compromission circulant sur les canaux Telegram et réseaux sociaux.
* Désigner un point de contact unique chargé de la vérification auprès des CERT et des autorités compétentes.
* Préparer des modèles de communication interne et externe pour les cas de rumeurs non corroborées.

#### Phase 2 — Détection et analyse

* Surveiller les canaux de diffusion d'allégations de compromission d'agences gouvernementales et journaliser leur propagation.
* Rechercher des indicateurs techniques corroborants dans les propres journaux (accès inhabituels, indisponibilité de services).
* Vérifier auprès des canaux officiels (CISA, éditeurs, CERT sectoriels) l'existence d'avis ou de confirmations.

#### Phase 3 — Confinement, éradication et récupération

* Ne pas relayer l'allégation sans corroboration afin d'éviter l'amplification.
* En cas de doute sur une compromission réelle, appliquer les mesures conservatoires habituelles : revue des accès à privilèges, MFA, journalisation renforcée.
* Limiter la communication aux faits vérifiés et documenter la source de l'allégation.

#### Phase 4 — Activités post-incident

* Clore formellement l'allégation (confirmée ou infirmée) et archiver les éléments de preuve.
* Mettre à jour la veille et les critères de qualification des sources non fiables.
* Former les équipes à distinguer bruit informationnel et signal CTI exploitable.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy/DNS des accès vers les canaux de diffusion cités depuis le réseau d'entreprise.
* Contrôler l'absence d'indisponibilité ou de comportement anormal sur les services critiques internes.
* Corréler avec les campagnes de désinformation connues visant les institutions.

---

### Sources

* [https://t.me/vxunderground/9618](https://t.me/vxunderground/9618)


---

<div id="etats-unis-le-fbi-vise-par-un-nouveau-piratage-ses-bases-de-donnees-criminelles-en-question"></div>

## États-Unis : Le FBI visé par un nouveau piratage, ses bases de données criminelles en question

### Résumé

Selon les éléments rapportés par NBC News et CNN, le FBI aurait été visé par un nouveau piratage mettant en cause ses bases de données criminelles. On ignore encore si les incidents sont liés entre eux et qui en est responsable.

---

### Analyse opérationnelle

Aucun indicateur technique n'est publié à ce stade, ce qui limite la détection directe. L'impact opérationnel porte sur la confidentialité des données d'enquête : exposition potentielle de sources, de témoins et de méthodes d'investigation, avec un risque d'usurpation d'identité d'agents et de campagnes de phishing ciblées utilisant des éléments d'enquête comme appât. Les équipes de sécurité des entités judiciaires et des partenaires doivent renforcer la surveillance des accès à privilèges, des exports de données et des comptes tiers, et vérifier la segmentation entre bases d'enquête et systèmes bureautiques.

---

### Implications stratégiques

La compromission de bases de données répressives touche à la confiance dans les institutions et à la sécurité des personnes collaborant avec elles. Elle peut alimenter l'extorsion, la désinformation et le discrédit des enquêtes en cours, avec des conséquences sur la coopération internationale et le partage de renseignement. La tendance est à la hausse des attaques contre les infrastructures gouvernementales et à la réutilisation des données d'enquête comme levier de pression géopolitique.

---

### Recommandations

* Renforcer l'authentification et la journalisation sur les bases de données d'enquête.
* Limiter et auditer les accès tiers aux systèmes d'information judiciaires.
* Surveiller les fuites de données gouvernementales sur les canaux cybercriminels.
* Protéger les personnes potentiellement exposées (agents, sources, témoins).
* Préparer une communication de crise maîtrisée et coordonnée avec les partenaires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les bases de données d'enquête et leurs niveaux de classification, ainsi que les tiers autorisés à y accéder.
* Vérifier les clauses de notification et les procédures internes de gestion de crise pour les systèmes judiciaires.
* Préparer des scénarios de compromission de données d'enquête (sources humaines, agents infiltrés, témoins).
* Mettre en place une surveillance des fuites sur les forums et canaux de revente de données gouvernementales.

#### Phase 2 — Détection et analyse

* Rechercher les accès anormaux aux bases de données criminelles (volumétrie d'export, requêtes massives, comptes tiers).
* Analyser les journaux d'authentification des comptes à privilèges et des accès distants.
* Corréler les publications médiatiques avec les traces techniques internes pour qualifier le périmètre.
* Surveiller l'apparition de jeux de données estampillés FBI sur les places de marché cybercriminelles.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les accès tiers non indispensables et renforcer l'authentification sur les systèmes d'information judiciaires.
* Segmenter les bases de données d'enquête du reste du SI et limiter les exports.
* Activer une surveillance renforcée des tentatives d'usurpation d'identité d'agents et de contacts d'enquête.
* Protéger les personnes potentiellement exposées (agents, sources, témoins) par des mesures de sécurité physique et numérique.

#### Phase 4 — Activités post-incident

* Conduire un audit des droits d'accès et des intégrations tierces sur les bases de données concernées.
* Renforcer la journalisation et la détection sur les systèmes d'enquête (DLP, UEBA).
* Réviser les procédures de partage d'information avec les partenaires nationaux et internationaux.
* Communiquer de manière maîtrisée pour préserver la confiance institutionnelle et la continuité des enquêtes.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des campagnes de phishing ciblant les agents utilisant des données d'enquête comme appât.
* Traquer les accès persistants non identifiés sur les systèmes d'information judiciaires.
* Surveiller les canaux de revente et les fuites progressives de données d'enquête.
* Analyser les corrélations entre les incidents multiples signalés et d'éventuelles infrastructures d'attaque communes.

---

### Sources

* [https://cyberveille.curated.co/issues/585](https://cyberveille.curated.co/issues/585)
* [https://mastodon.social/@cyberveille/117670381637660242](https://mastodon.social/@cyberveille/117670381637660242)


---

<div id="lia-detecte-desormais-des-failles-zero-day-pour-seulement-4"></div>

## L'IA détecte désormais des failles « zero-day » pour seulement 4$

### Résumé

Les progrès rapides des modèles d'intelligence artificielle permettraient de détecter plus facilement et à moindre coût des vulnérabilités critiques, avec un coût annoncé d'environ 4 dollars par détection. La source souligne qu'il s'agit d'une arme à double tranchant, également exploitable par les attaquants.

---

### Analyse opérationnelle

La baisse drastique du coût de la recherche de vulnérabilités augmente mécaniquement le volume de failles découvertes et réduit la fenêtre entre découverte et exploitation. Les équipes SOC/IT doivent anticiper une accélération du rythme de publication de CVE, une hausse des preuves de concept publiques et une pression accrue sur les cycles de patch. Les mesures techniques pertinentes incluent la priorisation par exploitabilité réelle (KEV, EPSS), l'automatisation de l'inventaire et de la corrélation vulnérabilités/actifs, le recours à des mesures compensatoires (WAF, segmentation) et le renforcement de la détection des scans et tentatives d'exploitation.

---

### Implications stratégiques

La démocratisation de la recherche offensive assistée par IA modifie l'équilibre entre attaquants et défenseurs : les organisations doivent réévaluer leurs délais de remédiation et leurs seuils de risque acceptables. Les éditeurs logiciels font face à une pression accrue sur la qualité de leurs produits et sur leurs processus de divulgation. Sur le plan décisionnel, cela plaide pour des investissements dans l'automatisation de la gestion des vulnérabilités et pour un encadrement de l'usage de l'IA en cybersécurité, tant offensif que défensif.

---

### Recommandations

* Réduire les délais de remédiation pour les actifs exposés à Internet.
* Prioriser les vulnérabilités selon l'exploitabilité réelle (KEV, EPSS) plutôt que le seul score CVSS.
* Automatiser la corrélation entre alertes de vulnérabilités et inventaire des actifs.
* Déployer des mesures compensatoires sur les systèmes non corrigeables rapidement.
* Encadrer l'usage interne de l'IA pour la recherche de vulnérabilités et la validation des correctifs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer les sources de renseignement sur les vulnérabilités (CVE, KEV, EPSS) dans un processus de priorisation automatisé.
* Définir des délais de remédiation différenciés selon la criticité et l'exposition externe des actifs.
* Cartographier la surface d'attaque externe et maintenir un inventaire à jour des versions logicielles.
* Préparer des capacités de test d'intrusion et de validation rapide des correctifs.

#### Phase 2 — Détection et analyse

* Surveiller les publications de vulnérabilités et les preuves de concept publiées, en particulier sur les technologies exposées.
* Détecter les tentatives d'exploitation sur les services exposés (WAF, IDS, journaux applicatifs).
* Corréler les alertes de vulnérabilités avec la télémétrie de l'inventaire pour identifier les actifs réellement affectés.
* Analyser les pics d'activité de scan et de fuzzing ciblant les applications métier.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer les mesures compensatoires (WAF, segmentation, désactivation de fonctionnalités) en attendant les correctifs.
* Prioriser le patch des actifs exposés à Internet et des systèmes critiques.
* Isoler les services vulnérables non corrigeables dans les délais impartis.
* Renforcer la surveillance des comptes à privilèges sur les systèmes récemment corrigés.

#### Phase 4 — Activités post-incident

* Mesurer le délai réel entre publication d'une vulnérabilité et remédiation complète.
* Réviser les processus de gestion des correctifs et les seuils de tolérance au risque.
* Évaluer l'apport des outils d'IA dans la détection interne de vulnérabilités et encadrer leur usage.
* Mettre à jour la politique de divulgation et les relations avec les chercheurs.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs d'exploitation de vulnérabilités récentes sur les actifs exposés.
* Traquer les comportements post-exploitation sur les services récemment patchés.
* Analyser les journaux de scan et de fuzzing pour identifier des reconnaissances automatisées.
* Surveiller les modèles et services d'IA utilisés pour la découverte de vulnérabilités et leurs usages malveillants.

---

### Sources

* [https://cyberveille.curated.co/issues/585](https://cyberveille.curated.co/issues/585)
* [https://mastodon.social/@cyberveille/117670381637660242](https://mastodon.social/@cyberveille/117670381637660242)


---

<div id="noel-ces-mots-de-passe-qui-fragilisent-la-securite-des-entreprises"></div>

## Noël : ces mots de passe qui fragilisent la sécurité des entreprises

### Résumé

Pour déterminer à quelle fréquence les références festives apparaissent dans les mots de passe, l'équipe de recherche de Specops a analysé plus de 260 millions de mots de passe compromis identifiés en 2026. L'étude met en évidence la persistance de mots de passe faibles liés aux périodes de fêtes dans les environnements d'entreprise.

---

### Analyse opérationnelle

Les mots de passe saisonniers sont exploitables par pulvérisation (password spraying) et par credential stuffing à partir de bases de fuites. Les équipes SOC doivent surveiller les schémas d'échecs d'authentification distribués sur de nombreux comptes, les connexions réussies depuis des localisations inhabituelles et l'usage de variantes prévisibles (nom d'entreprise + année + référence festive). Les mesures techniques incluent le blocage des mots de passe compromis dans l'annuaire, l'application généralisée du MFA, le verrouillage progressif et la détection des attaques par pulvérisation.

---

### Implications stratégiques

Le facteur humain reste un vecteur majeur, avec un pic de risque pendant les périodes de faible supervision et de forte activité sociale (phishing de fin d'année). Les conséquences décisionnelles portent sur la gouvernance des identités, la conformité aux exigences NIS2 et la nécessité d'investir dans des contrôles d'authentification résistants au phishing plutôt que dans des politiques de complexité de mots de passe.

---

### Recommandations

* Bloquer les mots de passe issus de fuites connues et les références saisonnières dans l'annuaire.
* Généraliser l'authentification multifacteur, en privilégiant les facteurs résistants au phishing.
* Détecter les attaques par pulvérisation via la corrélation des échecs d'authentification.
* Lancer une campagne de sensibilisation avant les fêtes et un exercice de phishing simulé.
* Renforcer la supervision des accès pendant les périodes de faible effectif.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre à jour la politique de mots de passe : longueur minimale, blocage des mots de passe compromis et des références saisonnières.
* Déployer l'authentification multifacteur sur l'ensemble des accès distants et des applications critiques.
* Intégrer une liste noire de mots de passe issus de fuites connues dans l'Active Directory / IdP.
* Prévoir une campagne de sensibilisation saisonnière (période des fêtes) sur les risques de mots de passe faibles.

#### Phase 2 — Détection et analyse

* Surveiller les échecs d'authentification répétés et les schémas de pulvérisation (nombreux comptes, peu de tentatives par compte).
* Détecter les connexions réussies depuis des localisations ou des appareils inhabituels.
* Analyser les journaux d'authentification pour identifier l'usage de mots de passe saisonniers ou triviaux.
* Corréler avec les fuites de mots de passe connues pour identifier les comptes à risque.

#### Phase 3 — Confinement, éradication et récupération

* Forcer la réinitialisation des mots de passe des comptes détectés comme faibles ou compromis.
* Bloquer temporairement les adresses IP sources des tentatives de pulvérisation et activer un verrouillage progressif.
* Révoquer les sessions actives des comptes suspects et exiger une réauthentification MFA.
* Notifier les utilisateurs concernés et fournir un canal de signalement des tentatives de phishing.

#### Phase 4 — Activités post-incident

* Évaluer l'efficacité de la politique de mots de passe et des contrôles MFA.
* Mettre à jour les règles de détection et les listes noires de mots de passe.
* Intégrer les enseignements dans le programme de sensibilisation et les exercices de phishing.
* Mesurer la conformité aux exigences réglementaires (NIS2, ISO 27001) sur la gestion des identifiants.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des comptes utilisant des variantes de mots de passe saisonniers ou de marque.
* Traquer les connexions réussies après une série d'échecs sur le même compte ou sur plusieurs comptes.
* Analyser les accès aux applications critiques pendant les périodes de faible supervision (fêtes).
* Surveiller les jeux d'identifiants d'entreprise sur les places de marché cybercriminelles.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1110.003** | Force brute : pulvérisation de mots de passe (password spraying) sur des références saisonnières |
| **T1078** | Utilisation de comptes valides obtenus via des mots de passe faibles ou réutilisés |

---

### Sources

* [https://cyberveille.curated.co/issues/585](https://cyberveille.curated.co/issues/585)
* [https://mastodon.social/@cyberveille/117670381637660242](https://mastodon.social/@cyberveille/117670381637660242)


---

<div id="les-passerelles-serie-industrielles-diffusent-quelles-sont-non-securisees"></div>

## Les passerelles série industrielles diffusent qu'elles sont non sécurisées

### Résumé

Dark Reading rapporte que les passerelles série industrielles, équipements d'accès critiques pour les environnements OT, diffusent elles-mêmes leur état de sécurité : elles indiquent à quiconque les interroge si elles sont protégées par une authentification. De nombreux équipements déployés ne le sont pas, ce qui expose directement les environnements industriels à des accès non autorisés.

---

### Analyse opérationnelle

L'impact est double. D'abord, la phase de reconnaissance est triviale : un attaquant n'a pas besoin d'exploiter une vulnérabilité, il suffit d'interroger l'équipement pour savoir s'il est protégé. Ensuite, l'absence d'authentification sur ces passerelles donne un accès direct aux réseaux série et donc aux automates et équipements de procédé en aval. Pour le SOC, la priorité est l'inventaire exhaustif des passerelles série (constructeur, firmware, emplacement réseau, présence d'authentification) et la réduction de la surface d'exposition : aucun accès Internet entrant, segmentation OT/IT stricte, filtrage des flux vers les seuls ports et protocoles nécessaires. La détection repose sur la surveillance des requêtes d'identification et des connexions d'administration hors fenêtres de maintenance. La réponse doit être coordonnée avec les équipes production pour éviter tout arrêt de procédé lors de l'isolation ou de la mise à jour d'un équipement.

---

### Implications stratégiques

Cette faiblesse illustre la persistance de mauvaises pratiques de sécurité sur des équipements OT souvent installés il y a plus de dix ans et rarement mis à jour. Elle crée un risque systémique pour les opérateurs d'importance vitale (énergie, eau, transport, manufacturing) et un enjeu de conformité direct avec NIS2 et IEC 62443. La décision à porter au niveau direction est celle d'un programme d'assainissement OT budgété : inventaire, remplacement des équipements non patchables, et gouvernance des accès distants des intégrateurs et mainteneurs tiers.

---

### Recommandations

* Inventorier toutes les passerelles série et qualifier leur niveau d'authentification.
* Interdire tout accès Internet entrant vers les interfaces d'administration OT.
* Remplacer les identifiants par défaut et désactiver Telnet/HTTP en clair.
* Segmenter les équipements OT et n'autoriser que les flux strictement nécessaires.
* Mettre en place une supervision des tentatives d'accès et des scans vers la zone OT.
* Planifier le remplacement des équipements non corrigeables et documenter les exceptions.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser toutes les passerelles série/converters OT (Moxa, Digi, Perle, équivalents) avec firmware, version, emplacement réseau et propriétaire.
* Vérifier systématiquement la présence d'authentification et le changement des identifiants par défaut avant mise en service.
* Segmenter les équipements OT dans une zone dédiée avec filtrage strict Nord-Sud et aucun accès direct depuis Internet.
* Cartographier les flux légitimes (ports TCP/4001, 502, 102, 23, 443 selon constructeur) pour permettre la détection d'anomalies.
* Aligner les mesures sur IEC 62443 et les obligations de notification NIS2 applicables au site.

#### Phase 2 — Détection et analyse

* Surveiller les requêtes de découverte/identification émises vers les passerelles série depuis des sources non autorisées.
* Alerter sur toute connexion aboutie vers une interface d'administration de passerelle sans authentification préalable.
* Détecter les tentatives de connexion en série (brute force, énumération de ports) sur les plages OT.
* Corréler les logs de pare-feu OT avec les journaux des équipements pour identifier les accès hors plages de maintenance.
* Rechercher les réponses d'équipements révélant l'absence d'authentification lors de scans internes.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement du réseau les passerelles non authentifiées ou exposées, sans interrompre les procédés critiques (coordination avec les équipes production).
* Bloquer au niveau du pare-feu OT tout accès Internet entrant vers les interfaces d'administration.
* Activer ou renforcer l'authentification, remplacer les identifiants par défaut, désactiver les services inutiles (Telnet, HTTP clair).
* Appliquer les mises à jour firmware constructeur et, à défaut, compenser par une ACL ou un proxy d'administration.
* Conserver les preuves (captures de configuration, logs) avant remédiation.

#### Phase 4 — Activités post-incident

* Mettre à jour l'inventaire OT et la matrice de flux après remédiation.
* Documenter les écarts de configuration et les exceptions acceptées avec validation formelle du risk owner.
* Renforcer la procédure de mise en service (security by design) et les tests d'acceptation sécurité.
* Planifier un audit de configuration récurrent des équipements de conversion série.
* Briefing direction et conformité sur l'exposition résiduelle et les obligations réglementaires.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement les scans et connexions vers les passerelles série sur 90 jours.
* Identifier les équipements ayant répondu à des requêtes d'identification non sollicitées.
* Vérifier l'absence de modification de configuration ou de firmware non planifiée.
* Contrôler les accès sortants inhabituels depuis la zone OT vers Internet.
* Comparer les configurations actuelles à une baseline de référence pour détecter les dérives.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595** | Balayage actif : les passerelles série industrielles annoncent elles-mêmes leur état d'authentification, facilitant le repérage des équipements non protégés. |
| **T1190** | Exploitation d'une application/équipement exposé sur Internet : accès non authentifié aux interfaces de passerelles série. |
| **T1078** | Utilisation de comptes par défaut ou absents pour accéder aux équipements OT. |

---

### Sources

* [https://www.darkreading.com/ics-ot-security/industrial-serial-gateways-broadcast-insecure](https://www.darkreading.com/ics-ot-security/industrial-serial-gateways-broadcast-insecure)


---

<div id="oxloader-exploite-le-detournement-de-dll-pour-distribuer-differentes-familles-de-logiciels-malveillants"></div>

## OXLoader exploite le détournement de DLL pour distribuer différentes familles de logiciels malveillants

### Résumé

Malwarebytes observe une recrudescence d'activité autour d'OXLoader, un loader qui installe d'autres malwares sur la machine. Elastic l'avait documenté en juin 2026 dans une campagne utilisant Google Ads pour diffuser CASTLESTEALER via OXLoader. Selon la campagne, OXLoader distribue Remcos, OverLord, PureRAT, Lunex Stealer, LOLD et Hermes, permettant le vol de mots de passe enregistrés dans le navigateur, la prise de contrôle à distance du poste ou le téléchargement de charges supplémentaires. La nouveauté observée par Malwarebytes est l'usage du DLL hijacking pour déchiffrer et exécuter OXLoader : plusieurs DLL légitimes sont détournées (Qt5Widgets.dll, Qt6Core.dll, SDL3.dll, UnityPlayer.dll, ANCUtility.dll, dbghelp.dll, msvcr100.dll, WindowsCodecs.dll), associées à des exécutables de Microsoft, Steam, OBS Studio et de lecteurs PDF/Word. Les vecteurs reposent sur de faux avis de plainte pour violation de droits d'auteur (PDF en pièce jointe menant à une archive ZIP), des fichiers .bat aux noms très longs, des archives nommées Evidence_of_Violation.zip hébergées sur Google Sites, et de faux activateurs de logiciels téléchargés depuis GitLab.

---

### Analyse opérationnelle

OXLoader est un loader générique : la détection doit porter sur le mécanisme (DLL hijacking, déchiffrement en mémoire, exécution depuis des répertoires utilisateur) plutôt que sur une famille de payload unique. Concrètement, les équipes SOC doivent surveiller le chargement de DLL connues depuis des chemins non standards, en particulier à côté d'exécutables signés légitimes, ainsi que les processus signés chargeant des DLL non signées ou récemment écrites. Les fichiers .bat aux noms très longs et les archives ZIP à thème juridique sont des indicateurs à fort signal. La réponse doit inclure la rotation des identifiants navigateur, la révocation de sessions et la reconstruction du poste, un RAT ayant été déployé dans la majorité des chaînes. Les contrôles les plus rentables sont l'application allowlisting (WDAC/AppLocker), le blocage des exécutables en pièce jointe et la restriction des téléchargements depuis les hébergeurs grand public.

---

### Implications stratégiques

La campagne illustre l'industrialisation du modèle « loader-as-a-service » : un même chargeur sert plusieurs familles, ce qui brouille l'attribution et allonge la durée de vie des infrastructures. Le recours à des leurres juridiques (fausses plaintes pour contrefaçon) exploite la pression hiérarchique et la peur de l'utilisateur, un levier psychosocial efficace en entreprise. L'usage de plateformes légitimes (GitLab, Google Sites, Google Ads) comme infrastructure de diffusion complique le filtrage et déplace le risque vers la gouvernance des usages SaaS. Pour la direction, l'enjeu est la maîtrise des logiciels non autorisés sur les parcs, souvent tolérés en pratique, et la couverture EDR des postes hors périmètre strict.

---

### Recommandations

* Bloquer les pièces jointes exécutables et les doubles extensions au niveau de la messagerie.
* Déployer un allowlisting applicatif (WDAC/AppLocker) pour neutraliser le DLL hijacking.
* Interdire l'installation d'activateurs et de logiciels piratés, et le rappeler via la sensibilisation.
* Surveiller le chargement de DLL non signées par des processus signés (Sysmon Event ID 7).
* Bloquer les téléchargements d'archives depuis les hébergeurs grand public sur les postes utilisateurs.
* En cas d'infection : rotation des identifiants navigateur, révocation des sessions et réinstallation du poste.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Bloquer au niveau mail et proxy les extensions exécutables et les doubles extensions (.docx.exe, .pdf.exe) ainsi que les .bat en pièce jointe.
* Restreindre l'exécution aux binaires signés et aux chemins autorisés (AppLocker/WDAC) pour limiter le DLL hijacking.
* Désactiver ou restreindre l'installation de logiciels non autorisés, y compris activateurs et cracks.
* Sensibiliser les utilisateurs aux leurres « plainte pour violation de droits d'auteur » et aux faux activateurs.
* Activer la journalisation Sysmon (chargement d'images, création de processus, connexions réseau) sur les postes Windows.

#### Phase 2 — Détection et analyse

* Détecter le chargement de DLL connues détournées (Qt5Widgets.dll, Qt6Core.dll, SDL3.dll, UnityPlayer.dll, ANCUtility.dll, dbghelp.dll, msvcr100.dll, WindowsCodecs.dll) depuis des répertoires non standards ou aux côtés d'exécutables inattendus.
* Alerter sur les processus légitimes (Microsoft, Steam, OBS Studio, lecteurs PDF/Word) chargeant des DLL non signées ou récemment écrites.
* Repérer les fichiers .bat aux noms très longs contenant des motifs de type Review_Front_Back ou Product_Review_Order.
* Surveiller les archives ZIP nommées Evidence_of_Violation.zip ou téléchargées depuis des sites d'hébergement grand public.
* Détecter les connexions sortantes vers des infrastructures de RAT/stealer et les injections dans des processus navigateur.

#### Phase 3 — Confinement, éradication et récupération

* Isoler la machine compromise du réseau sans l'éteindre pour préserver la mémoire.
* Tuer les processus malveillants et supprimer les points de persistance identifiés (Run keys, tâches planifiées, services).
* Réinitialiser tous les mots de passe enregistrés dans les navigateurs et révoquer les sessions actives.
* Bloquer les domaines, URL et hachages identifiés au niveau proxy, DNS et EDR.
* Rechercher la latéralisation et l'exfiltration avant toute remise en service du poste.

#### Phase 4 — Activités post-incident

* Reconstruire le poste à partir d'une image saine plutôt que nettoyer un système ayant hébergé un RAT.
* Analyser la chaîne d'infection complète (e-mail d'origine, URL de téléchargement, DLL détournée) et documenter les IOC.
* Notifier l'utilisateur et, le cas échéant, les tiers dont les identifiants auraient pu être exposés.
* Mettre à jour les règles de détection et les listes de blocage avec les artefacts de la campagne.
* Revoir les politiques d'exécution applicative et de filtrage web/mail.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur 90 jours les exécutions de .bat téléchargeant des archives ZIP depuis des hébergeurs publics.
* Identifier les postes ayant chargé des DLL dupliquées ou non signées à proximité d'exécutables légitimes.
* Rechercher les artefacts des familles déployées : Remcos, OverLord, PureRAT, Lunex Stealer, LOLD, Hermes, CASTLESTEALER.
* Analyser les accès aux sites de type Google Sites ou GitLab hébergeant de faux activateurs.
* Vérifier les connexions sortantes anormales depuis les postes utilisateurs vers des VPS ou hébergeurs low-cost.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1574.001** | DLL Search Order Hijacking : OXLoader est déchiffré et exécuté via des DLL légitimes détournées (Qt5Widgets.dll, Qt6Core.dll, SDL3.dll, UnityPlayer.dll, ANCUtility.dll, dbghelp.dll, msvcr100.dll, WindowsCodecs.dll). |
| **T1566.001** | Pièce jointe d'hameçonnage : PDF ou e-mail évoquant une plainte pour violation de droits d'auteur incitant à télécharger et exécuter une archive ZIP. |
| **T1204.002** | Exécution par l'utilisateur d'un fichier malveillant (exécutable, fichier .bat, faux activateur de logiciel). |
| **T1027** | Obfuscation : charge utile OXLoader chiffrée, déchiffrée à l'exécution par la DLL détournée. |
| **T1105** | Transfert d'outils entrants : fichiers .bat téléchargeant une archive ZIP contenant la DLL malveillante depuis différents hébergeurs. |
| **T1555** | Vol d'identifiants stockés dans les navigateurs via les stealers déployés (CASTLESTEALER, Lunex Stealer). |
| **T1219** | Accès distant via RAT (Remcos, OverLord, PureRAT) pour prise de contrôle de la machine Windows. |

---

### Sources

* [https://www.malwarebytes.com/blog/threat-intel/2026/11/oxloader-abuses-dll-hijacking-to-distribute-different-malware-families](https://www.malwarebytes.com/blog/threat-intel/2026/11/oxloader-abuses-dll-hijacking-to-distribute-different-malware-families)


---

<div id="sunnybrookca-par-scarlettgroup"></div>

## sunnybrook.ca par scarlettgroup

### Résumé

Le site de fuite du groupe de rançongiciel Scarlettgroup recense 13 publications au total, dont 8 sur les 30 derniers jours et 7 sur les 7 derniers jours, avec un uptime moyen de 58 % sur 30 jours et une dernière publication le 2026-11-24 à 23:17. Deux miroirs .onion sont suivis : l'un est indiqué comme indisponible (13-17 % d'uptime), l'autre comme disponible à 100 %. Les victimes publiées le 2026-11-24 sont sunnybrook.ca (hôpital universitaire de Toronto), spencers.com (retail américain), medinahealthcare.net (système de santé du Texas), sigsauer.com (fabricant d'armes à feu), fittleworth.com (fournisseur de matériel médical britannique), chu-bordeaux.fr (CHU français) et knox.edu (collège de l'Illinois). Des publications antérieures (octobre 2026) concernent mahsing.com.my, vinsolutions.com, genesys.com, nbcuniversal.com, police.rajasthan.gov.in et yalebooks.yale.edu.

---

### Analyse opérationnelle

Le rythme de publication (7 victimes en 7 jours) indique un groupe actif et opérationnel, malgré une infrastructure instable (un miroir majoritairement indisponible). La concentration sectorielle est marquée : santé (Sunnybrook, Medina Healthcare, Fittleworth, CHU de Bordeaux), éducation (Knox College, Yale University Press), industrie de défense (SIG SAUER), forces de l'ordre (Rajasthan Police) et médias (NBCUniversal). Pour un SOC, ces publications doivent être traitées comme des signaux de compromission potentielle : vérifier l'exposition des accès distants (VPN, RDP, portails), l'activité des comptes à privilèges et les journaux de sauvegarde. Les domaines listés sont des victimes présumées et non de l'infrastructure attaquante : ils ne doivent pas être bloqués mais surveillés (recherche de credentials fuités, de règles de messagerie malveillantes, de persistance). L'absence de détail sur le vecteur d'accès initial impose une chasse large sur les TTP classiques de double extorsion.

---

### Implications stratégiques

La publication simultanée d'un CHU français et d'un hôpital canadien confirme que le secteur de la santé reste une cible prioritaire, avec un risque direct sur la continuité des soins et une exposition RGPD/notification aux autorités. La présence de SIG SAUER et de la police du Rajasthan élargit la menace à la base industrielle de défense et aux institutions régaliennes, avec un risque d'espionnage au-delà de la seule extorsion financière. L'émergence d'un groupe à faible maturité d'infrastructure mais à forte cadence de publication illustre la démocratisation du modèle rançongiciel-as-a-service et la nécessité d'une surveillance continue des sites de fuite comme source de renseignement précoce.

---

### Recommandations

* Surveiller quotidiennement les miroirs Scarlettgroup et intégrer les victimes publiées dans la veille sectorielle.
* Imposer le MFA sur tous les accès distants et restreindre l'exposition RDP/VPN.
* Vérifier l'absence de règles de messagerie malveillantes et de sessions actives suspectes sur les comptes Microsoft 365/Google Workspace.
* Tester la restauration des sauvegardes immuables et vérifier la segmentation des sauvegardes du réseau de production.
* Préparer un scénario de crise incluant notification CNIL/autorité de tutelle sous 72h pour les entités françaises concernées.
* Partager les IOC confirmés avec les CERT sectoriels santé et les pairs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les actifs exposés sur Internet (VPN, RDP, portails web, appliances edge) et vérifier la couverture EDR sur les serveurs de fichiers et hyperviseurs.
* Valider les sauvegardes hors ligne/immuables et tester une restauration complète pour les applications critiques (SIR, DPI, messagerie).
* Préparer une cellule de crise incluant direction, juridique, communication, DPO et CNIL/autorité de tutelle pour le secteur santé.
* Mettre en place une surveillance des sites de fuite .onion (dont les miroirs Scarlettgroup) et des flux de renseignement sur les groupes émergents.
* Vérifier les procédures de notification de violation (RGPD 72h) et les contrats cyber/rançon.

#### Phase 2 — Détection et analyse

* Surveiller l'apparition du nom de domaine de l'organisation sur les miroirs Scarlettgroup et autres sites de fuite.
* Corréler les alertes EDR/AV avec des indicateurs de chiffrement massif, de suppression de clichés instantanés (vssadmin, wbadmin) et de désactivation des sauvegardes.
* Détecter les connexions VPN/RDP anormales, les créations de comptes privilégiés et les mouvements latéraux (SMB, WMI, PsExec).
* Analyser les journaux de proxy/DNS pour identifier des exfiltrations vers des services de stockage ou des canaux C2 (MEGA, rclone, FTP custom).
* Activer une chasse ciblée sur les comptes de service et les identités cloud après toute alerte d'authentification suspecte.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments réseau compromis et couper les accès VPN/SSL-VPN suspects sans interrompre les soins critiques.
* Réinitialiser les identifiants à privilèges (krbtgt x2, comptes admin, comptes de service) et révoquer les sessions et jetons OAuth.
* Bloquer les URL .onion et les IOC connus au niveau proxy/pare-feu et restreindre les sorties Internet non nécessaires.
* Préserver les preuves (images disque, journaux, mémoire) avant toute remédiation et ouvrir une main courante horodatée.
* Communiquer avec l'autorité de tutelle et, le cas échéant, avec les forces de l'ordre (ANSSI, OCLCTIC, Europol) avant toute interaction avec les attaquants.

#### Phase 4 — Activités post-incident

* Réaliser un retour d'expérience formel sur le vecteur d'accès initial et les délais de détection/containment.
* Renforcer la segmentation IT/OT, le MFA sur tous les accès distants et la gestion des comptes à privilèges (PAM).
* Mettre à jour les plans de continuité et tester la restauration des données à partir des sauvegardes immuables.
* Suivre l'évolution de la publication des données volées et préparer la communication aux patients/partenaires si des données personnelles sont exposées.
* Réévaluer la posture de threat intelligence et intégrer Scarlettgroup dans la liste de surveillance des groupes émergents.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts associés aux miroirs Scarlettgroup (URL .onion, hash de session) dans les journaux de proxy et de DNS.
* Chasser les TTP de double extorsion : accès initial via VPN/edge, vol de credentials, exfiltration via outils légitimes (rclone, 7zip, WinSCP).
* Analyser les comptes créés/modifiés dans les 30 jours précédant une éventuelle compromission et les connexions hors horaires.
* Vérifier la présence de balises/notes de rançon et de fichiers aux extensions inhabituelles sur les partages réseau.
* Partager les IOC confirmés avec les CERT sectoriels et les pairs du secteur santé.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxp://scarlettgugldabhgz3uertpnxglxytddxbd5vnoma5pihfk6k5q2sid[.]onion/` | High |
| URL | `hxxp://scarlettgugldabhgz3uertpnxglxytddxbd5vnoma5pihfk6k5q2sid[.]onion/breaches` | High |
| URL | `hxxp://scarlettgutttdlyxz6rdqfslpdvdqnnzuxvzfsqavys2hvtnd3aidyd[.]onion/` | High |
| URL | `hxxp://scarlettgutttdlyxz6rdqfslpdvdqnnzuxvzfsqavys2hvtnd3aidyd[.]onion/breaches` | High |
| HASH_SHA256 | `05866673bcba27e7713eec9bbf6ffe0d01895d522b321e8dda7056e4172115b32e` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1657** | Financial Theft — extorsion via site de fuite (double extorsion) |
| **T1486** | Data Encrypted for Impact — chiffrement des systèmes des victimes |
| **T1567** | Exfiltration Over Web Service — publication des données volées sur le site .onion |

---

### Sources

* [https://www.ransomlook.io//group/scarlettgroup](https://www.ransomlook.io//group/scarlettgroup)


---

<div id="peninsula-energy-suspend-la-cotation-apres-quun-incident-cyber-a-touche-une-mine-duranium-americaine"></div>

## Peninsula Energy suspend la cotation après qu'un incident cyber a touché une mine d'uranium américaine

### Résumé

La société australienne Peninsula Energy (ASX : PEN ; OTCQB : PENMF) a demandé la suspension de cotation après un incident de cybersécurité survenu dans la nuit du vendredi sur son site minier de Lance Project, dans le Wyoming (États-Unis). Dans un dépôt à l'ASX lundi, la société indique qu'une enquête préliminaire et une évaluation du calendrier et de l'impact sont en cours, et que l'incident affectera temporairement ses opérations. Le dépôt précise que l'incident a entraîné une violation de son « operating system », tandis que les systèmes administratifs aux États-Unis et en Australie n'ont pas été affectés. La société n'a pas précisé quels systèmes techniques ont été compromis ni si la production d'uranium a été interrompue. La suspension de cotation doit rester en place jusqu'à la reprise des échanges le 25 novembre 2026 ou jusqu'à la publication d'une annonce sur l'incident. Le Lance Project repose sur l'extraction par récupération in situ, produisant du yellowcake destiné au combustible nucléaire. L'article rappelle que l'uranium a été ajouté en 2025 à la liste fédérale américaine des minéraux critiques, que des acteurs de menace ont mené des campagnes d'influence contre des sociétés de terres rares aux États-Unis et en Australie, et qu'AngloGold Ashanti a déclaré le 16 octobre une activité non autorisée sur certains systèmes. Dragos a observé 19 attaques par rançongiciel contre des organisations minières entre juillet et septembre 2026.

---

### Analyse opérationnelle

L'atteinte d'un « operating system » sur un site minier suggère une compromission du réseau opérationnel ou des systèmes de supervision industrielle, avec un impact direct sur la production et non sur la bureautique — un schéma typique de ciblage OT. Pour un SOC/IT, la priorité est de vérifier la segmentation IT/OT, l'inventaire des accès distants (prestataires, ingénierie, maintenance) et la journalisation des automates. L'absence de revendication et d'IOC publiés impose une chasse sur les TTP de rançongiciel industriel : mouvements latéraux IT→OT, vol d'identifiants d'ingénierie, altération de configurations d'automates. La suspension de cotation ajoute une pression de communication financière qui peut accélérer la divulgation avant la fin de l'investigation, avec un risque de fuite d'informations.

---

### Implications stratégiques

Le ciblage d'une mine d'uranium aux États-Unis s'inscrit dans une tendance de fond : l'uranium est devenu un minéral critique en 2025 et le Lance Project est présenté comme un fournisseur clé de la chaîne d'approvisionnement nucléaire américaine. La convergence entre intérêts étatiques (approvisionnement énergétique, dissuasion), activisme et cybercriminalité rend ces sites stratégiques. L'incident, survenu trois semaines après la divulgation d'AngloGold Ashanti et dans un contexte de 19 attaques rançongiciel contre le secteur minier au troisième trimestre 2026, confirme l'intensification du ciblage de l'industrie extractive en Amérique du Nord et en Europe. Les conséquences décisionnelles portent sur l'obligation de transparence boursière, la continuité de production et la protection des infrastructures critiques de la chaîne nucléaire.

---

### Recommandations

* Vérifier et renforcer la segmentation entre réseaux IT et OT, avec inspection des flux et bastion d'administration dédié.
* Recenser et durcir les accès distants des prestataires OT (MFA, comptes nominatifs, journalisation, expiration).
* Déployer une supervision comportementale des réseaux industriels (passive monitoring) sur les sites miniers et de traitement.
* Préparer un plan de continuité spécifique à l'arrêt des systèmes opérationnels et tester les procédures de redémarrage sécurisé.
* Coordonner la communication de crise avec les obligations d'information continue de l'autorité boursière.
* Suivre les campagnes ransomware ciblant le secteur minier et partager les renseignements avec les CERT sectoriels.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les systèmes du site minier (SCADA, automates, réseau OT, télémetrie ISR) et vérifier la segmentation IT/OT.
* Identifier les dépendances aux systèmes d'administration (RH, finance, messagerie) et les accès distants des sous-traitants et prestataires OT.
* Préparer un plan de continuité pour l'extraction in situ et le traitement du yellowcake en cas d'arrêt des systèmes opérationnels.
* Établir les canaux de communication avec l'autorité boursière (ASX), les régulateurs nucléaires et les autorités cyber.
* Vérifier la disponibilité de sauvegardes hors ligne des configurations d'automates et des historiques de production.

#### Phase 2 — Détection et analyse

* Surveiller les alertes EDR/NDR sur les postes d'ingénierie et les serveurs de supervision reliés au réseau OT.
* Détecter les connexions anormales vers les automates (Modbus, OPC, DNP3) et les changements de configuration non planifiés.
* Analyser les journaux d'authentification pour identifier des accès distants inhabituels (VPN, RDP, comptes de sous-traitants).
* Corréler les événements IT et OT pour repérer un pivot depuis le réseau bureautique vers le réseau industriel.
* Mettre en place une surveillance des communications sortantes inhabituelles depuis les segments OT.

#### Phase 3 — Confinement, éradication et récupération

* Isoler le segment OT impacté tout en maintenant les fonctions de sécurité physique et de sûreté du site.
* Suspendre les accès distants des tiers et révoquer les identifiants potentiellement compromis.
* Bloquer les flux C2 identifiés et déconnecter les systèmes d'administration non essentiels.
* Préserver les preuves forensiques (images, journaux, captures réseau) avant remédiation.
* Coordonner la communication de crise avec l'ASX et respecter les obligations d'information continue.

#### Phase 4 — Activités post-incident

* Réaliser une analyse post-incident sur le vecteur d'accès initial et l'étendue du compromis IT/OT.
* Renforcer la segmentation, la supervision OT et le contrôle des accès tiers (bastion, MFA, revue des droits).
* Mettre à jour le plan de réponse OT et tester les procédures d'arrêt/démarrage sécurisé des opérations minières.
* Revoir les contrats avec les prestataires OT pour inclure des exigences de notification d'incident et de sécurité.
* Communiquer aux actionnaires et aux régulateurs les mesures correctives mises en œuvre.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts de mouvements latéraux IT vers OT (PsExec, RDP, partages administratifs) dans les journaux.
* Chasser les accès non autorisés aux automates et les modifications de programmes ou de logiques de contrôle.
* Analyser les comptes créés ou modifiés récemment et les connexions hors horaires sur les systèmes d'ingénierie.
* Rechercher des indicateurs de rançongiciel ou de wiper sur les serveurs d'administration et les postes d'ingénierie.
* Comparer les activités observées aux campagnes récentes ciblant le secteur minier (Dragos, groupes ransomware industriels).

---

### Sources

* [https://www.securityweek.com/peninsula-energy-halts-trading-after-cyber-incident-hits-us-uranium-mine/](https://www.securityweek.com/peninsula-energy-halts-trading-after-cyber-incident-hits-us-uranium-mine/)
