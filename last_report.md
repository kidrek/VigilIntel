# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Formbook cible les entreprises européennes de l'industrie manufacturière et de la technologie avec des leurres de commande localisés](#formbook-cible-les-entreprises-europeennes-de-lindustrie-manufacturiere-et-de-la-technologie-avec-des-leurres-de-commande-localises)
  * [Astuce de développement de malware 70 : injection de processus par point d'arrêt matériel. Exemple simple en C](#astuce-de-developpement-de-malware-70-injection-de-processus-par-point-darret-materiel-exemple-simple-en-c)
  * [Détecter les agents dormants cachés dans les neurones des modèles d'IA](#detecter-les-agents-dormants-caches-dans-les-neurones-des-modeles-dia)
  * [Le réseau de fraude DoppelCart dépasse les 250 000 domaines](#le-reseau-de-fraude-doppelcart-depasse-les-250-000-domaines)
  * [GhostFrame : un nouvel implant ESXi lié au ransomware Settra](#ghostframe-un-nouvel-implant-esxi-lie-au-ransomware-settra)
  * [Cet exploit viral de triangulation Doppler d'aéronef ? J'en ai construit une réplication fonctionnelle.](#cet-exploit-viral-de-triangulation-doppler-daeronef-jen-ai-construit-une-replication-fonctionnelle)
  * [NukeRat Framework : un framework post-exploitation pour les opérations avancées de Red Team](#nukerat-framework-un-framework-post-exploitation-pour-les-operations-avancees-de-red-team)
  * [Évolution des menaces informatiques au T3 2026. Statistiques mobiles](#evolution-des-menaces-informatiques-au-t3-2026-statistiques-mobiles)
  * [Comment exporter les journaux de Cortex XDR, Cortex XSIAM, LimaCharlie et Amazon Security Lake](#comment-exporter-les-journaux-de-cortex-xdr-cortex-xsiam-limacharlie-et-amazon-security-lake)
  * [KongTuke ClickFix s'en prend à un trésor canadien : Canada Dry](#kongtuke-clickfix-sen-prend-a-un-tresor-canadien-canada-dry)
  * [🇮🇷#Iranul, acuzat de atacul asupra frigiderelor din 🇫🇷#Franța. O amenințare 🇮🇷#Iraniană ar fi pus și armata 🇺🇸#SUA în alertă.](#iranul-acuzat-de-atacul-asupra-frigiderelor-din-franta-o-amenintare-iraniana-ar-fi-pus-si-armata-sua-in-alerta)
  * [Publications sur des sites de fuite de ransomware : incransom, Bravox et PixelLeaks revendiquent des victimes dans les secteurs juridique, de la santé, manufacturier et du transport](#publications-sur-des-sites-de-fuite-de-ransomware-incransom-bravox-et-pixelleaks-revendiquent-des-victimes-dans-les-secteurs-juridique-de-la-sante-manufacturier-et-du-transport)
  * [SG : SPH Media victime de cyberattaques ; déclare qu'aucune donnée financière client ni aucun accès n'a été exposé](#sg-sph-media-victime-de-cyberattaques-declare-quaucune-donnee-financiere-client-ni-aucun-acces-na-ete-expose)
  * [Binance qualifie de tentative d'arnaque la publication attribuée à ShinyHunters](#binance-qualifie-de-tentative-darnaque-la-publication-attribuee-a-shinyhunters)
  * [Des données de patients de Weill Cornell saisies dans des outils d'IA sans autorisation](#des-donnees-de-patients-de-weill-cornell-saisies-dans-des-outils-dia-sans-autorisation)
  * [L'Australie va introduire une obligation de signalement après le piratage d'OpenAI pour lutter contre l'IA qui « devient incontrôlable »](#laustralie-va-introduire-une-obligation-de-signalement-apres-le-piratage-dopenai-pour-lutter-contre-lia-qui-devient-incontrolable)
  * [Le modèle Mythos d'Anthropic, super détecteur de bugs, arrive dans les produits de Cisco et IBM](#le-modele-mythos-danthropic-super-detecteur-de-bugs-arrive-dans-les-produits-de-cisco-et-ibm)
  * [L'entreprise russe de cloud Beget reconstruit de zéro après une attaque par effaceur de données](#lentreprise-russe-de-cloud-beget-reconstruit-de-zero-apres-une-attaque-par-effaceur-de-donnees)
  * [Remus Stealer commercialise un accès persistant à Gmail – Hudson Rock enquête](#remus-stealer-commercialise-un-acces-persistant-a-gmail-hudson-rock-enquete)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La journée est dominée par les vulnérabilités avec 106 entrées, ce qui impose une priorisation rapide des correctifs exposés et des actifs critiques. Les 33 incidents de fuite de données confirment une pression persistante sur les données clients et partenaires, avec un risque réputationnel et réglementaire accru. Les 9 éléments géopolitiques suggèrent un contexte de menaces étatiques et de hacktivisme à surveiller pour anticiper les campagnes ciblées. La veille réglementaire reste modérée (4 items) mais doit être intégrée aux décisions de conformité et de notification. Le faible volume d’acteurs de menace identifiés (1) ne doit pas masquer la réutilisation probable de modes opératoires connus dans les brèches et exploitations de vulnérabilités. Les 19 articles de contexte complètent le renseignement et orientent la chasse aux indicateurs vers les surfaces d’exposition les plus fréquentes. Recommandation du jour : accélérer la remédiation des vulnérabilités critiques, renforcer la détection sur les fuites de données et maintenir une veille géopolitique ciblée.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Turla** | secteur public, diplomatie, défense, administration | Backdoor sur serveurs Exchange, persistance, obfuscation, injection de processus, collecte de courriels et C2 HTTP. | T1505.003, T1071.001, T1027, T1055, T1140, T1114.002 | `hxxps://securityaffairs[.]com/202800/apt/russia-linked-apt-turla-turned-exchange-servers-into-their-own-control-room[.]html` |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Amérique latine, Asie, Europe** | Télécommunications, administrations publiques, défense, recherche, infrastructure critique | Espionnage cyber d'origine chinoise : le framework Sparrow et l'entité CopperDragon | Check Point Research documente une année d'enquête sur trois clusters distincts — SilentDelivery (Europe/Asie), OceanGate (Asie) et DarkWire (Amérique latine) — qui ciblent opérateurs télécoms, administrations, entités militaires, instituts de recherche et infrastructures critiques. Ces clusters se présentent d'abord comme des opérations indépendantes, avec des portes dérobées et des rythmes opérationnels différents, mais l'analyse relie leurs infrastructures et leur code à un même écosystème malveillant : le framework Sparrow (variantes Windows et Linux, backdoor passive, lien avec Melofee). L'entité désignée sous le nom de CopperDragon est présentée comme un « quartermaster » numérique, probable développeur/fournisseur d'outils pour plusieurs acteurs liés à la Chine (FamousSparrow, Earth Estries, TropicTrooper, UAT-9244, avec un lien historique flou vers Salt Typhoon). Le mode d'accès initial varie : compromission d'infrastructures exposées à Internet (notamment des systèmes Linux faisant pivot vers Windows) et watering holes très sélectifs sur des sites gouvernementaux, maritimes, IT et de recherche, avec diffusion de la backdoor SquadC via des installateurs MSI trojanisés déguisés en utilitaires de réparation de certificats. Implications CTI : la mutualisation d'un arsenal commun entre plusieurs groupes brouille l'attribution et crée un effet de levier (un même outil réutilisé sur plusieurs théâtres) ; la chaîne d'approvisionnement logicielle (MSI signés/trojanisés) et les sites web légitimes deviennent des vecteurs de choix ; la persistance sur Linux exposé et le pivot vers Windows compliquent la détection périmétrique classique. La convergence télécoms/administrations/défense suggère une priorité au renseignement d'État plutôt qu'à la monetisation. | [https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/](https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/) |
| **États-Unis, Amériques, Europe** | Politique intérieure et politique étrangère | Midterms américaines : recompositions politiques et conséquences géopolitiques | Entretien IRIS entre Pascal Boniface et Marie-Cécile Naves consacré aux résultats des élections de mi-mandat aux États-Unis. Les démocrates obtiennent la majorité dans les deux chambres du Congrès, infligeant une défaite au camp républicain et à Donald Trump. L'analyse porte sur deux effets possibles : la recomposition des rapports de force politiques internes (capacité de l'exécutif à légiférer, enquêtes parlementaires, blocages budgétaires) et l'inflexion de la stratégie internationale américaine. Pour la CTI, l'enjeu est indirect mais réel : un Congrès hostile peut modifier le financement de l'aide à l'Ukraine, les crédits de défense, la politique technologique et les régimes de sanctions, donc le paysage des menaces étatiques et des contre-mesures économiques. Le contenu source reste un cadrage général, sans détail programmatique ; les conclusions doivent donc être traitées comme des hypothèses à confirmer par les votes budgétaires à venir. | [https://www.iris-france.org/recompositions-geopolitique-et-politique-aux-etats-unis/](https://www.iris-france.org/recompositions-geopolitique-et-politique-aux-etats-unis/) |
| **Turquie, Australie, Europe, Moyen-Orient, Asie** | Climat, énergie, diplomatie multilatérale | COP31 à Antalya : ambitions climatiques dans un monde fragmenté | La COP31 s'ouvre le 9 novembre 2026 à Antalya (Turquie) jusqu'au 20 novembre, avec une configuration inédite de double présidence : la Turquie assure l'hôte et l'Agenda de l'action, l'Australie conduit les négociations, faute d'accord pour renoncer à la présidence. Le contexte est doublement dégradé. Sur le plan climatique, l'OMM situe 2026 dans une série de records : été parmi les plus chauds, surmortalité (près de 8 000 décès en France), incendies massifs (76 000 hectares en France, Indonésie, Canada), mousson historiquement faible en Inde, crue glaciaire meurtrière au Népal, le tout amplifié par un El Niño hors norme. Sur le plan géopolitique, la fragmentation du multilatéralisme s'aggrave : poursuite de l'invasion russe en Ukraine, escalade au Moyen-Orient avec une guerre menée par les États-Unis et Israël contre l'Iran en février 2026 et blocage du détroit d'Ormuz, avec des répercussions mondiales sur l'énergie et les engrais. La COP reste la seule enceinte réunissant près de 200 États sur la gouvernance climatique, ce qui en fait un point d'observation clé des tensions entre sécurité énergétique, sécurité alimentaire et action climatique. | [https://www.iris-france.org/cop31-quelles-ambitions-climatiques-dans-un-monde-fragmente/](https://www.iris-france.org/cop31-quelles-ambitions-climatiques-dans-un-monde-fragmente/) |
| **Caraïbe, Amériques, Mexique, Venezuela** | Défense et sécurité, aide humanitaire d'urgence, environnement | Opérations HADR et risque cyclonique dans la Caraïbe insulaire face au dérèglement climatique | Note de Laurent Giacobbi (IRIS, Observatoire Défense et Climat) sur un espace fragmenté de plus de 4 000 km, du Yucatán au Venezuela, réunissant 13 États souverains et 17 micro-territoires américains, britanniques, français et néerlandais. Malgré son émiettement archipélagique et sa diversité économique et culturelle, la région forme un espace stratégique cohérent : interface des Amériques, proximité du canal de Panama, routes commerciales, migratoires et de narcotrafic, intégration aux intérêts de sécurité des États-Unis. Le risque cyclonique est le principal facteur d'unité : les ouragans majeurs frappent des populations et des infrastructures littorales concentrées, et dépassent rapidement les capacités nationales des petits États insulaires. Les opérations HADR y associent administrations locales, organisations régionales, institutions internationales, ONG et forces armées, ces dernières intervenant surtout dans les premières phases grâce à leurs moyens de projection, de commandement et de soutien. La note analyse l'évolution du risque, les tensions de l'architecture HADR et les recompositions géopolitiques qu'elle révèle, notamment la concurrence d'influence entre puissances extérieures dans une zone historiquement sous influence américaine. | [https://www.iris-france.org/les-operations-hadr-dans-la-caraibe-insulaire-a-lheure-du-dereglement-climatique/](https://www.iris-france.org/les-operations-hadr-dans-la-caraibe-insulaire-a-lheure-du-dereglement-climatique/) |
| **France** | OSINT, veille, formation et sensibilisation | Lancement du Tour de France de la Fresque de la Connaissance | Annonce du lancement d'un « Tour de France de la Fresque de la Connaissance », initiative de sensibilisation et de pédagogie autour de la connaissance, de la veille et de l'OSINT, portée par la communauté francophone de l'intelligence économique. Le contenu source est limité à l'annonce : pas de détail sur les étapes, les partenaires ni le programme. L'intérêt pour une équipe CTI est indirect mais concret : ces formats participent à la montée en compétence des praticiens, à la structuration de réseaux professionnels et à la diffusion de bonnes pratiques en collecte et analyse d'information ouverte. Aucun élément de menace, aucun indicateur technique. | [https://www.portail-ie.fr/univers/osint-et-veille/2026/lancement-du-tour-de-france-de-la-fresque-de-la-connaissance/](https://www.portail-ie.fr/univers/osint-et-veille/2026/lancement-du-tour-de-france-de-la-fresque-de-la-connaissance/) |
| **Ukraine, Russie, Europe, États-Unis** | Défense, diplomatie, industrie de défense | Garanties de sécurité post-guerre pour l'Ukraine : pourquoi une garantie « de type article 5 » est peu crédible | Commentaire RUSI critiquant l'idée, évoquée par Volodymyr Zelensky après un échange avec Steve Witkoff le 20 octobre à Oslo, d'une garantie de sécurité bilatérale américaine calquée sur l'article 5 de l'OTAN, concept repris par des dirigeants européens. L'auteur juge cette promesse peu crédible : l'administration Trump a réduit son soutien à l'Ukraine et veut diminuer le rôle américain en Europe ; même un président plus favorable serait confronté à l'exigence de crédibilité, qui suppose une volonté démontrée d'engagement direct. Les précédents cités — garantie américaine à la Corée du Sud après l'armistice de 1953, garantie à l'Allemagne de l'Ouest à son entrée dans l'OTAN en 1955 — reposaient sur le stationnement durable de dizaines de milliers de soldats américains, rendant une attaque adverse synonyme de guerre directe avec les États-Unis. La coalition européenne a par ailleurs posé des conditions si strictes à un déploiement (cessez-le-feu total, accord russe, dos américain explicite) qu'il est difficile d'imaginer sa matérialisation. L'alternative proposée : des accords juridiquement codifiés garantissant, pour au moins une décennie après la guerre, un flux régulier d'armes, de formation, de coopération industrielle de défense et de partage de renseignement, afin que la dissuasion — par déni et par punition — repose sur les capacités ukrainiennes elles-mêmes, y compris des frappes longue portée. | [https://www.rusi.org/explore-our-research/publications/commentary/why-article-5-style-guarantee-ukraine-makes-little-sense](https://www.rusi.org/explore-our-research/publications/commentary/why-article-5-style-guarantee-ukraine-makes-little-sense) |
| **États-Unis, Chine** | Technologie, semi-conducteurs, économie | Affaire d'espionnage chez Nvidia : la face cachée de la guerre froide technologique sino-américaine | Article du Monde consacré à un scandale d'espionnage chez Nvidia, présenté comme révélateur de la « face cachée » de la guerre froide technologique entre Washington et Pékin. Le contenu accessible se limite à l'annonce et à un interstitiel de vérification de navigateur : ni les acteurs mis en cause, ni les données concernées, ni le mode opératoire ne sont disponibles dans la source. L'analyse doit donc rester prudente et se limiter au cadrage : dans un contexte de contrôle des exportations sur les puces avancées, d'accusations croisées de pénétration de chaînes d'approvisionnement et de concurrence pour les talents, les entreprises de semi-conducteurs deviennent à la fois cibles de renseignement économique et objets de controverses politico-judiciaires. Le risque principal pour les organisations du secteur est double : exfiltration de propriété intellectuelle et de feuilles de route produits, et exposition réputationnelle/réglementaire liée aux enquêtes. | [https://www.lemonde.fr/economie/article/2026/11/10/le-scandale-d-espionnage-chez-nvidia-revele-la-face-cachee-de-la-guerre-froide-technologique-a-laquelle-se-livrent-les-etats-unis-et-la-chine_6808810_3234.html](https://www.lemonde.fr/economie/article/2026/11/10/le-scandale-d-espionnage-chez-nvidia-revele-la-face-cachee-de-la-guerre-froide-technologique-a-laquelle-se-livrent-les-etats-unis-et-la-chine_6808810_3234.html) |
| **Kazakhstan, Roumanie, Europe, Asie centrale** | Administrations publiques, diplomatie, défense, alliances internationales | Turla (FSB) : le toolset « Cereal » détourne les serveurs Exchange gouvernementaux pour espionner les échanges NATO/UE | ESET documente un toolset modulaire .NET inédit, baptisé « Cereal » en raison de son usage intensif de la sérialisation, implanté sur des serveurs Microsoft Exchange de deux organisations gouvernementales : l'une au Kazakhstan, compromise le 28 novembre 2025, l'autre en Roumanie, compromise le 23 décembre 2025 et configurée pour repérer les courriels échangés avec l'OTAN et l'Union européenne. L'attribution à Turla (groupe aligné sur la Russie, largement évalué comme relevant du FSB, actif depuis au moins 2004) est faite avec un haut niveau de confiance, sur la base de l'usage concomitant d'un autre composant publiquement attribué à Turla et de similarités conceptuelles avec des malwares plus anciens. Points saillants : absence d'infrastructure de commande et contrôle externe — le serveur Exchange compromis sert lui-même de point de contrôle, ce qui complique la détection réseau ; backdoor passive donnant accès au réseau interne ; commandes livrées sous forme d'exécutables séparés de structure personnalisée, suggérant un framework automatisant la compilation et la livraison ; module de collecte automatisée injecté dans les processus Exchange légitimes, manipulant le pipeline de transport des courriels, ce qui exige une connaissance approfondie des internes d'Exchange ; recours à des techniques .NET avancées (points d'entrée non managés, abus du cache d'images natives .NET). Il s'agit d'une compromission de longue durée, non d'une exploitation massive de vulnérabilités. | [https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/)<br>[https://infosec.exchange/@cyberseckyle/117594418282553699](https://infosec.exchange/@cyberseckyle/117594418282553699) |
| **France, Iran, Europe, Danemark** | Grande distribution, IoT/OT, chaîne d'approvisionnement agroalimentaire | Cyberattaque iranienne contre les systèmes de réfrigération de supermarchés français : attribution, démenti et perspective de riposte | En octobre 2026, les systèmes de régulation frigorifique du fabricant danois Danfoss, utilisés dans plus de 400 supermarchés en France, ont été la cible d'une cyberattaque d'ampleur. Le 9 novembre, la France a officiellement attribué l'opération à une unité cyber relevant du corps des Gardiens de la Révolution islamique (IRGC) — l'unité Shahid Kaveh selon Le Monde. Le 10 novembre, Téhéran a rejeté des « accusations infondées ». L'Union européenne a qualifié la situation de « cyberattaques répétées préoccupantes ». Le gouvernement français a déclaré ne « s'interdit rien » en matière de riposte, ouvrant la voie à des mesures de rétorsion non précisées. L'affaire illustre plusieurs tendances lourdes : la cible n'est pas un opérateur stratégique classique mais une chaîne d'équipements OT/IoT largement diffusée, avec un effet de contagion via un fournisseur unique ; la sous-estimation de la menace par certains acteurs économiques et la fragmentation des responsabilités entre fabricant, intégrateur et exploitant compliquent la remédiation ; l'attribution publique par un État européen transforme un incident de sécurité en acte de politique étrangère, avec un risque d'escalade et de représailles croisées. Le démenti iranien est conforme au schéma habituel de déni plausible des opérations iraniennes, tandis que la mention d'une unité nommée suggère un niveau de confiance élevé des services français. | [https://www.france24.com/fr/vid%C3%A9o/20261110-cyberattaques-l-iran-rejette-les-accusations-infond%C3%A9es-de-la-france](https://www.france24.com/fr/vid%C3%A9o/20261110-cyberattaques-l-iran-rejette-les-accusations-infond%C3%A9es-de-la-france)<br>[https://www.france24.com/fr/vid%C3%A9o/20261110-france-des-cyberattaques-r%C3%A9p%C3%A9t%C3%A9es-pr%C3%A9occupantes-d-apr%C3%A8s-l-union-europ%C3%A9enne](https://www.france24.com/fr/vid%C3%A9o/20261110-france-des-cyberattaques-r%C3%A9p%C3%A9t%C3%A9es-pr%C3%A9occupantes-d-apr%C3%A8s-l-union-europ%C3%A9enne)<br>[https://www.france24.com/fr/france/20261110-cyberattaque-contre-des-frigos-la-france-dit-ne-s-interdit-rien-dans-la-riposte-contre-l-iran](https://www.france24.com/fr/france/20261110-cyberattaque-contre-des-frigos-la-france-dit-ne-s-interdit-rien-dans-la-riposte-contre-l-iran)<br>[https://www.lemonde.fr/international/article/2026/11/10/cyberattaque-contre-des-refrigerateurs-de-supermarches-l-iran-rejette-les-accusations-infondees-de-la-france_6808797_3211.html](https://www.lemonde.fr/international/article/2026/11/10/cyberattaque-contre-des-refrigerateurs-de-supermarches-l-iran-rejette-les-accusations-infondees-de-la-france_6808797_3211.html)<br>[https://www.lemonde.fr/pixels/article/2026/11/10/derriere-la-cyberattaque-contre-les-frigos-de-supermarches-l-iran-et-l-unite-cyber-des-gardiens-de-la-revolution_6808819_4408996.html](https://www.lemonde.fr/pixels/article/2026/11/10/derriere-la-cyberattaque-contre-les-frigos-de-supermarches-l-iran-et-l-unite-cyber-des-gardiens-de-la-revolution_6808819_4408996.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| US-CISA-DIRECTOR-NOMINATION-LOSAPIO | Maison-Blanche / Sénat des États-Unis / CISA (Cybersecurity and Infrastructure Security Agency) / DHS | 2026-11-10 | États-Unis (niveau fédéral) | US-CISA-DIRECTOR-NOMINATION-LOSAPIO | Le président Donald Trump a nommé le 9 novembre 2026 Michael LoSapio, CISO de Palantir, à la direction de la CISA. Cette nomination intervient dans un contexte de vacance prolongée : aucun directeur confirmé par le Sénat n'a dirigé l'agence depuis le début du second mandat de Trump, le premier candidat Sean Plankey ayant retiré sa candidature en avril après treize mois de blocages sénatoriaux. Le calendrier est contraint : la session lame-duck a débuté le 9 novembre, les républicains conservent la majorité du Sénat jusqu'en janvier, et le directeur par intérim Nick Andersen ne pouvait légalement occuper ce poste que jusqu'au 23 novembre (210 jours après le retrait formel de la nomination de Plankey) ; le dépôt d'une nouvelle nomination pourrait suspendre ce décompte. Le profil de LoSapio (CISO de Palantir depuis septembre 2024, près de sept ans à la tête de la sécurité des infrastructures du groupe, arrivé en 2013) correspond à la recherche par l'administration d'un dirigeant issu d'une grande entreprise technologique. La nomination est toutefois politiquement sensible : Palantir a obtenu en février un accord d'achat en source unique couvrant l'ensemble des agences du DHS, et des parlementaires démocrates (Ron Wyden, Dan Goldman, Nydia Velázquez et une trentaine d'autres) réclament depuis avril la divulgation de tous les contrats Palantir depuis 2020 et des jeux de données alimentant les systèmes utilisés dans l'application des lois sur l'immigration, dénonçant un « écosystème de surveillance de masse » ; Palantir conteste ces allégations. Sur le fond, les observateurs attendent du futur directeur une doctrine claire sur l'IA générative et le « Secure by Design » (génération de code sûr, conversion de code C vers des langages à mémoire sûre, refonte des composants défaillants de la chaîne d'approvisionnement logicielle) plutôt qu'une approche de correction a posteriori des défauts. Un second point de friction persiste : la publication d'un rapport public sur la cybersécurité des télécommunications, toujours attendu par le sénateur Wyden. | [https://www.healthcareinfosecurity.com/trump-taps-palantir-ciso-to-lead-cisa-a-33349](https://www.healthcareinfosecurity.com/trump-taps-palantir-ciso-to-lead-cisa-a-33349)<br>[https://cyberscoop.com/trump-picks-palantirs-losapio-to-head-cisa/](https://cyberscoop.com/trump-picks-palantirs-losapio-to-head-cisa/) |
| FR-UE-NIS2-DORA-CRA-BERCY-CYBER-2026 | ANSSI, Ministère de l'Économie (Bercy), Commission européenne, CESIN, MEDEF | 2026-11-10 | France / Union européenne | FR-UE-NIS2-DORA-CRA-BERCY-CYBER-2026 | La première édition du « Bercy de la Cyber », tenue le 29 octobre 2026 et ouverte par Anne Le Hénanff et Roland Lescure, illustre le basculement de la cybersécurité vers un enjeu de sécurité économique et de compétitivité. Le Panorama de la cybermenace 2025 de l'ANSSI recense 3 586 événements de sécurité en un an, avec un espionnage principalement attribué à des acteurs liés à la Russie et à la Chine pratiquant le pré-positionnement, et des cibles de sabotage privilégiées dans les télécommunications et l'énergie. Le vecteur d'entrée dominant reste les équipements de bordure (pare-feu, passerelles VPN exposées), souvent exploités avant publication du correctif, et la frontière entre groupes étatiques et cybercriminels s'estompe, compliquant l'attribution. Le paradoxe central : des attaques sophistiquées réussissent via des failles élémentaires (mot de passe faible, équipement non mis à jour, sauvegarde non testée), concentrées dans les petites structures — 39 % des TPE-PME déclarent un incident cyber sur un an selon le baromètre France Num 2026, ce que l'ANSSI qualifie de « défi du dernier kilomètre ». Sur le volet réglementaire, la transposition de NIS2, qui étendrait les obligations à près de 15 000 entités françaises classées essentielles ou importantes, n'est toujours pas votée deux ans après l'échéance européenne ; le texte bute notamment sur un article relatif au chiffrement. En attendant, l'ANSSI a publié en mars le Référentiel Cyber France (ReCyF), fixant quinze objectifs de sécurité (vingt pour les entités essentielles, dont cinq portant sur l'audit et la supervision) avec des « moyens acceptables de conformité » opposables en contrôle, mais qui reste un document de travail sans base légale. Ce flou a un coût : selon le président du CESIN, de nombreuses ETI et grandes entreprises ont gelé leurs budgets de sécurité pour 2027, et les industriels jugent le ReCyF inadapté à leurs environnements (« on ne patche pas une usine comme un serveur »). La pression réglementaire se déplace par ailleurs vers la chaîne d'approvisionnement : NIS2 impose l'évaluation des prestataires, y compris les PME sous-traitantes souvent dépendantes d'une informatique externalisée, le MEDEF plaidant pour qu'elles sachent au moins « poser les bonnes questions ». Le Cyber Resilience Act ajoute depuis septembre une obligation de notification sous 24 heures de toute vulnérabilité activement exploitée, pour une application complète en décembre 2027. Le secteur financier, soumis à DORA depuis janvier 2025, apparaît en avance (registre des prestataires, déclaration des incidents majeurs, tests d'intrusion). | [https://www.portail-ie.fr/univers/risques-et-gouvernance-cyber/2026/nis2-dora-cra-ce-que-le-bercy-de-la-cyber-revele-du-retard-francais-en-cybersecurite/](https://www.portail-ie.fr/univers/risques-et-gouvernance-cyber/2026/nis2-dora-cra-ce-que-le-bercy-de-la-cyber-revele-du-retard-francais-en-cybersecurite/) |
| AU-AI-REGULATION-GOV-PLATFORM-BREACH | Gouvernement australien (régulateur IA et autorités cyber à préciser) | 2026-11-10 | Australie | AU-AI-REGULATION-GOV-PLATFORM-BREACH | Le contenu de la source n'était pas accessible au moment de l'analyse (page de vérification de navigateur), seule l'annonce éditoriale est exploitable : l'Australie entend renforcer sa régulation de l'intelligence artificielle après la compromission de plateformes gouvernementales par un modèle d'OpenAI. Les éléments factuels (vecteur exact, périmètre des données exposées, statut du modèle — agent autonome, plugin, accès API — et base légale invoquée) restent à confirmer. La portée réglementaire est néanmoins significative : elle suggère que le débat australien glisse de la régulation des usages vers la responsabilité des fournisseurs de modèles et la sécurité des systèmes agentiques, avec un précédent où un modèle d'IA est présenté comme le vecteur d'une intrusion dans des systèmes d'État. Ce type d'incident alimente les exigences de sécurité by design pour les fournisseurs, de journalisation et de limitation des capacités d'action des agents, ainsi que les obligations de notification d'incident. | [https://www.lemonde.fr/pixels/article/2026/11/10/l-australie-va-renforcer-sa-regulation-de-l-ia-apres-un-piratage-de-plateformes-gouvernementales-par-un-modele-d-openai_6808770_4408996.html](https://www.lemonde.fr/pixels/article/2026/11/10/l-australie-va-renforcer-sa-regulation-de-l-ia-apres-un-piratage-de-plateformes-gouvernementales-par-un-modele-d-openai_6808770_4408996.html) |
| TECH-NTLMV1-SSP-DOWNGRADE-WS2022 | N/A — recherche technique (article de sécurité offensive, hors périmètre réglementaire strict) | 2026-11-10 | N/A — environnements Microsoft Windows / Active Directory | TECH-NTLMV1-SSP-DOWNGRADE-WS2022 | Article technique (non réglementaire) démontrant que les environnements Windows Server 2022 restent vulnérables au downgrade NTLMv1 dès lors que le niveau d'authentification LAN Manager l'autorise. Rappel du mécanisme : le hash NT (MD4 d'un mot de passe UTF-16LE) est découpé en trois blocs de 7 octets utilisés comme clés DES pour chiffrer le challenge serveur de 8 octets, produisant CT1/CT2/CT3 concaténés en une réponse de 24 octets. Avec un challenge fixe et connu (par exemple 1122334455667788), chaque ciphertext devient précalculable par table arc-en-ciel, ce qui permet de remonter au hash NT puis au mot de passe. ESS (Extended Session Security), natif en NTLMv2 et optionnel en NTLMv1, introduit un challenge côté client qui neutralise les tables arc-en-ciel, mais peut être négocié à la baisse si le client accepte du NTLMv1 standard. Le levier de configuration est la stratégie de groupe « Network security: LAN Manager authentication level » (Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options) : les niveaux 0 à 2 autorisent NTLMv1 et rouvrent la voie au downgrade. La chaîne d'attaque décrite combine Responder configuré avec le challenge fixe et l'option --disable-ess, puis une coercition d'authentification depuis le contrôleur de domaine (PetitPotam) vers l'hôte attaquant, les journaux affichant alors des tentatives « NTLMv1-SSP » (le fournisseur SSP NTLM traitant NTLMv1, et non un protocole distinct). L'impact est la récupération hors ligne du hash NT, donc une compromission de credentials exploitable en pass-the-hash ou pour du cassage de mots de passe. | [https://hunio.org/security/ntlmv1-ssp-cracking/](https://hunio.org/security/ntlmv1-ssp-cracking/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Cloud / Plateforme de développement (PaaS)** | Railway (plateforme cloud de déploiement) | Identifiants et accès aux comptes de la plateforme, clés API et tokens de déploiement, secrets applicatifs stockés dans les projets, données de facturation et coordonnées de paiement | Inconnu | `hxxps://www[.]bleepingcomputer[.]com/news/apple/railway-breach-leads-to-740-000-in-fraudulent-ai-charges/` |
| **Hébergement web / Fournisseur de services Internet** | DreamHost (hébergeur web) | Identifiants de connexion FTP, sessions de webmail actives, adresses e-mail et potentiellement contenus des sites et boîtes mail hébergés | Inconnu | `hxxps://www[.]bleepingcomputer[.]com/news/security/dreamhost-confirms-data-breach-exposed-ftp-logins-and-webmail-sessions` |
| **Jeu vidéo / Divertissement** | SEGA (newsletter) | Adresses e-mail des abonnés à la newsletter (environ 2,2 millions), potentiellement noms, préférences et données d'inscription associées | 2200000 | `hxxps://www[.]bleepingcomputer[.]com/news/security/sega-newsletter-data-breach-exposes-22-million-email-addresses/` |
| **Enseignement supérieur / Université** | Université de York (York University) | Informations personnelles historiques remontant à 2007 : noms, coordonnées, identifiants étudiants et professionnels, données académiques et potentiellement données RH et documents administratifs | Inconnu | `hxxps://www[.]bleepingcomputer[.]com/news/security/york-university-breach-exposed-personal-information-dating-to-2007/` |
| **Secteur public / Gouvernement (messagerie institutionnelle)** | Organismes gouvernementaux au Kazakhstan et en Roumanie (serveurs Microsoft Exchange) | Courriers électroniques et pièces jointes des organismes gouvernementaux, métadonnées de messagerie, carnets d'adresses, communications avec l'OTAN et l'Union européenne, potentiellement identifiants et secrets d'administration du serveur Exchange | Inconnu | `hxxps://securityaffairs[.]com/202800/apt/russia-linked-apt-turla-turned-exchange-servers-into-their-own-control-room[.]html` |
| **Mobile / cryptomonnaies** | Écosystème iOS (utilisateurs d'applications de portefeuille crypto, dont les clients de Binance) | Aucune donnée compromise confirmée à ce stade. Données à risque : seed phrases et clés privées de portefeuilles crypto, identifiants de connexion et jetons de session stockés localement par les applications iOS, fichiers applicatifs divers accessibles via les App Group containers. | Inconnu | [https://securityaffairs.com/202788/hacking/ios-sandbox-escape-is-public-and-apple-hasnt-confirmed-a-fix.html](https://securityaffairs.com/202788/hacking/ios-sandbox-escape-is-public-and-apple-hasnt-confirmed-a-fix.html) |
| **Commerce de détail / biens de consommation (Japon)** | Iris Ohyama / Iris Plaza (Japon) | Données personnelles d'environ 7,7 millions de clients d'Iris Plaza : noms, mots de passe et autres informations de compte stockées dans le service cloud externe. Le détail complet du périmètre n'a pas été publié. | 7700000 | [https://securityaffairs.com/202740/data-breach/iris-ohyama-data-breach-may-expose-personal-information-of-7-7-million-people.html](https://securityaffairs.com/202740/data-breach/iris-ohyama-data-breach-may-expose-personal-information-of-7-7-million-people.html) |
| **Cryptomonnaies / développement logiciel open source** | Développeurs de portefeuilles crypto : Chainapsis (vizor-wallet), Zingo Labs (zingo-common, zingolib), écosystèmes Keplr, Zcash, Vizor et Cosmos | Aucune exfiltration confirmée publiquement. Données visées : clés de signature des flux de mise à jour, identifiants GitHub et cloud, matériel de signature fastlane et Android, coffres chiffrés de l'outillage Keplr MCP, éléments du trousseau macOS et variables d'environnement des runners CI. | Inconnu | [https://opensourcemalware.com/blog/cryptocurrency-being-targeted-in-multi-faceted-attack](https://opensourcemalware.com/blog/cryptocurrency-being-targeted-in-multi-faceted-attack) |
| **Éducation** | Lake County School Board (Floride, États-Unis) | Dossiers scolaires, plans d'éducation individualisés (IEP) et informations relatives au handicap d'environ 47 000 élèves, contenus dans huit fichiers non expurgés transmis à un parent. | 47000 | [https://databreaches.net/2026/11/10/lake-county-school-board-seeks-injunction-requiring-a-parent-who-received-unredacted-data-because-of-the-districts-error-to-destroy-the-data/](https://databreaches.net/2026/11/10/lake-county-school-board-seeks-injunction-requiring-a-parent-who-received-unredacted-data-because-of-the-districts-error-to-destroy-the-data/) |
| **Intelligence artificielle / services cloud** | Near AI | Informations de compte d'environ 100 utilisateurs et données traitées par 18 agents IA hébergés sur l'infrastructure Near AI. Le détail des catégories de données exposées n'a pas été publié. | 100 | [https://databreaches.net/2026/11/10/near-ai-breach-exposes-user-details-and-data-from-18-ai-agents/](https://databreaches.net/2026/11/10/near-ai-breach-exposes-user-details-and-data-from-18-ai-agents/) |
| **Secteur associatif / organisation caritative (Canada)** | The Children's Foundation (Canada) | Non précisé à ce stade. Compte tenu de la nature de l'organisation, des données de bénéficiaires, de donateurs ou de bénévoles pourraient être concernées. | Inconnu | [https://databreaches.net/2026/11/10/ca-data-breach-at-the-childrens-foundation/](https://databreaches.net/2026/11/10/ca-data-breach-at-the-childrens-foundation/) |
| **Secteur public (Philippines)** | Dix agences gouvernementales philippines (déclarations à la National Privacy Commission) | Non précisé. Les données personnelles de citoyens traitées par les agences concernées sont potentiellement en cause, sans confirmation. | Inconnu | [https://databreaches.net/2026/11/10/ph-npc-receives-data-breach-reports-from-10-agencies/](https://databreaches.net/2026/11/10/ph-npc-receives-data-breach-reports-from-10-agencies/) |
| **Secteur financier (Corée du Sud)** | Financial Security Institute (Corée du Sud) | Non précisé. Compte tenu de la nature de l'entité, des données de supervision, des informations sur des incidents du secteur financier ou des données personnelles de collaborateurs pourraient être concernées. | Inconnu | [https://databreaches.net/2026/11/10/kr-financial-security-institute-reports-data-leak-following-hacking-incident/](https://databreaches.net/2026/11/10/kr-financial-security-institute-reports-data-leak-following-hacking-incident/) |
| **Grand public / sécurité des comptes** | Grand public / utilisateurs de mots de passe | N/A (aucune fuite spécifique décrite) | Inconnu | [https://www.pickr.com.au/how-to/2026/three-tips-to-make-passwords-and-logins-easier-and-safer](https://www.pickr.com.au/how-to/2026/three-tips-to-make-passwords-and-logins-easier-and-safer)<br>[https://mastodon.social/@pickr/117594791681534522](https://mastodon.social/@pickr/117594791681534522) |
| **Éducation** | Lake County School District (Floride, États-Unis) | Dossiers éducatifs, plans d'éducation individualisés et informations sur le handicap d'environ 47 000 élèves. | 47000 | [https://www.fox35orlando.com/news/lake-county-data-leak-thousands-student-records-mistakenly-released](https://www.fox35orlando.com/news/lake-county-data-leak-thousands-student-records-mistakenly-released)<br>[https://infosec.exchange/@PogoWasRight/117594539733771650](https://infosec.exchange/@PogoWasRight/117594539733771650) |
| **Commerce de détail / ameublement** | Nitori | Numéros de membre, noms, adresses email, adresses postales, numéros de téléphone, dates de naissance, genre et informations de commande ; mots de passe et données de carte bancaire non exposés selon l'entreprise. | 37620000 | [https://osintsights.com/nitori-breach-exposes-376m-customer-records?utm_source=mastodon&utm_medium=social](https://osintsights.com/nitori-breach-exposes-376m-customer-records?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117594167948872169](https://mastodon.social/@Analyst207/117594167948872169) |
| **Secteur public / gouvernement** | Dix agences gouvernementales — National Privacy Commission | Données personnelles de citoyens, détails non précisés. | Inconnu | [https://mastodon.social/@peacenjunity/117594167442324729](https://mastodon.social/@peacenjunity/117594167442324729) |
| **Jeux vidéo / divertissement** | Sega Corporation / Arara Corporation | 2 196 044 adresses email ; 92 273 enregistrements contenaient des informations supplémentaires liées à la livraison des newsletters. Pas de noms, dates de naissance, genre, adresses physiques, téléphones, cartes bancaires ni mots de passe selon Sega. | 2196044 | [https://beyondmachines.net/event_details/sega-reports-data-breach-following-unauthorized-access-to-third-party-provider-arara-c-v-j-g-k/gD2P6Ple2L](https://beyondmachines.net/event_details/sega-reports-data-breach-following-unauthorized-access-to-third-party-provider-arara-c-v-j-g-k/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117593688362878026](https://infosec.exchange/@beyondmachines1/117593688362878026) |
| **Hôtellerie / voyage** | Wyndham Hotels & Resorts | Noms, adresses email, numéros de membre Wyndham, jetons JWT de session, fichiers et documents internes ; nombre exact non déterminé. | Inconnu | [https://techcrunch.com/2026/11/09/hotel-giant-wyndham-exposed-customer-data-after-app-security-lapse/](https://techcrunch.com/2026/11/09/hotel-giant-wyndham-exposed-customer-data-after-app-security-lapse/)<br>[https://mastodon.thenewoil.org/@thenewoil/117593683190307801](https://mastodon.thenewoil.org/@thenewoil/117593683190307801) |
| **Santé / audiologie** | Amplifon | Noms, dates de naissance, coordonnées, numéros de permis de conduire, autres identifiants gouvernementaux, informations médicales et auditives, dates de service, numéros de dossier médical, assurances santé, numéros de sécurité sociale (limité) et informations financières (limité). | 1332826 | [https://beyondmachines.net/event_details/amplifon-reports-data-breach-affecting-over-one-million-healthcare-customers-o-6-r-1-4/gD2P6Ple2L](https://beyondmachines.net/event_details/amplifon-reports-data-breach-affecting-over-one-million-healthcare-customers-o-6-r-1-4/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117593452398897550](https://infosec.exchange/@beyondmachines1/117593452398897550) |
| **Intelligence artificielle — plateforme d'inférence et d'entraînement de modèles** | Fireworks AI | Informations de ressources client, adresses de facturation et de livraison, historique des factures et paiements, soldes de compte, parties de modèles et jeux de données incomplets ; pas de numéros de carte bancaire stockés. | Inconnu | [https://en.hacks.gr/fireworks-ai-prosvasi-se-stoicheia-pelaton-kai-se-orismenes-periptoseis-se-imiteli-montela/](https://en.hacks.gr/fireworks-ai-prosvasi-se-stoicheia-pelaton-kai-se-orismenes-periptoseis-se-imiteli-montela/)<br>[https://mastodon.social/@hacksgr/117593293721839527](https://mastodon.social/@hacksgr/117593293721839527)<br>[https://www.bleepingcomputer.com/news/security/fireworks-ai-discloses-new-breach-after-cloud-provider-hack/](https://www.bleepingcomputer.com/news/security/fireworks-ai-discloses-new-breach-after-cloud-provider-hack/)<br>[https://infosec.exchange/@edwardk/117591587607740142](https://infosec.exchange/@edwardk/117591587607740142) |
| **Santé — prestataire de soins à domicile (oxygénothérapie, ventilation)** | SOS Oxygène | Données personnelles et de santé de patients : identité, coordonnées, informations de prise en charge et de suivi médical (périmètre exact non confirmé publiquement). | 15000 | [https://infonewscyber.fr/info/sos-oxygene-une-faille-de-securite-pourrait-exposer-les-donnees-de-plu-5b21ea0bba9fd468](https://infonewscyber.fr/info/sos-oxygene-une-faille-de-securite-pourrait-exposer-les-donnees-de-plu-5b21ea0bba9fd468)<br>[https://infosec.exchange/@infonewscyber/117593178107145415](https://infosec.exchange/@infonewscyber/117593178107145415) |
| **Services numériques — infrastructure de développement (CI/CD managé)** | Blacksmith (fournisseur de runners CI/CD GitHub Actions) | Journaux de jobs CI (sortie console) susceptibles de contenir secrets, tokens, identifiants, clés d'API et variables d'environnement de clients. | Inconnu | [https://status.blacksmith.sh/cmw5fokyu013w13mrtneqjv5l](https://status.blacksmith.sh/cmw5fokyu013w13mrtneqjv5l)<br>[https://infosec.exchange/@securestep9/117593137305003056](https://infosec.exchange/@securestep9/117593137305003056) |
| **Voyage et tourisme — agence de voyage en ligne** | ezTravel (agence de voyage en ligne, Taïwan) | Noms, adresses e-mail, numéros de téléphone, détails d'achat et historique de réservation de plus de 690 000 membres. | 690000 | [https://beyondmachines.net/event_details/eztravel-discloses-data-breach-affecting-over-690000-members-c-m-j-y-i/gD2P6Ple2L](https://beyondmachines.net/event_details/eztravel-discloses-data-breach-affecting-over-690000-members-c-m-j-y-i/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117592980555839783](https://infosec.exchange/@beyondmachines1/117592980555839783) |
| **Logement social — bailleur social (Occitanie)** | Altéal (bailleur social, Occitanie) — via la cyberattaque de Maileva | Données personnelles de locataires transmises au prestataire d'impression : identité, adresse, coordonnées et éléments de dossier locatif (périmètre exact non communiqué). | Inconnu | [https://infonewscyber.fr/info/le-bailleur-social-alteal-confirme-une-exposition-des-donnees-de-ses-l-896765fc4b02e84e](https://infonewscyber.fr/info/le-bailleur-social-alteal-confirme-une-exposition-des-donnees-de-ses-l-896765fc4b02e84e)<br>[https://infosec.exchange/@infonewscyber/117592902260409634](https://infosec.exchange/@infonewscyber/117592902260409634) |
| **Enseignement supérieur et recherche** | Vanderbilt University | Revendiqué (non confirmé) : bases de données chiffrées ; données d'étudiants, d'employés et de recherche ; plus d'un million de numéros de sécurité sociale ; données personnelles et académiques associées. | 1000000 | [https://infosec.exchange/@AAKL/117593083537329405](https://infosec.exchange/@AAKL/117593083537329405)<br>[https://www.neowin.net/news/vanderbilt-university-suffers-potential-ransomware-attack-data-breach/](https://www.neowin.net/news/vanderbilt-university-suffers-potential-ransomware-attack-data-breach/)<br>[https://www.infosecurity-magazine.com/news/vanderbilt-university-cyber/](https://www.infosecurity-magazine.com/news/vanderbilt-university-cyber/)<br>[https://www.bleepingcomputer.com/news/security/vanderbilt-university-hit-in-byod-ransomware-attack-data-theft-claimed/](https://www.bleepingcomputer.com/news/security/vanderbilt-university-hit-in-byod-ransomware-attack-data-theft-claimed/) |
| **Matériel et stockage réseau — équipements NAS** | QNAP (NAS de clients compromis — campagne Plex2Shell) | Données stockées sur les NAS compromis : documents, sauvegardes, fichiers personnels et professionnels (périmètre variable selon les clients). | Inconnu | [https://infonewscyber.fr/info/qnap-le-fabricant-reconnait-des-cyberattaques-contre-les-nas-de-ses-cl-ea3407b238b00265](https://infonewscyber.fr/info/qnap-le-fabricant-reconnait-des-cyberattaques-contre-les-nas-de-ses-cl-ea3407b238b00265)<br>[https://infosec.exchange/@infonewscyber/117593040112752158](https://infosec.exchange/@infonewscyber/117593040112752158) |
| **Multi-secteurs — rapport de renseignement sur la menace (IA, services publics, universités, télécoms)** | Multiples (rapport Acronis TRU Cyber Pulse 2026 — agents IA, OpenClaw, Gitea, rançongiciels Qilin/LockBit 5.0/INC) | Données variées selon les campagnes : identifiants et sessions volés, dépôts de code source, secrets d'API, données d'entreprises et de particuliers, données de services d'urgence et gouvernementaux (Taïwan), données universitaires (Thaïlande) et données téléphoniques (Mexique). | Inconnu | [https://www.helpnetsecurity.com/2026/11/10/acronis-ai-agent-cyberattacks-report/](https://www.helpnetsecurity.com/2026/11/10/acronis-ai-agent-cyberattacks-report/)<br>[https://infosec.exchange/@edwardk/117591586222087785](https://infosec.exchange/@edwardk/117591586222087785) |
| **Cryptomonnaies / portefeuilles numériques (Web3, fintech)** | Keplr (wallet) / Web3Auth (fournisseur d'authentification sociale) | Clés privées de portefeuilles crypto créés via Google/Apple (Web3Auth) ; identités de comptes et actifs numériques associés ; adresses de portefeuilles et historiques de transactions ; fonds crypto (montant exact non confirmé, estimations entre 1 M$ et 6,01 M$ déplacés). | 44000 | [https://thehackernews.com/2026/11/web3auth-flaw-exploited-to-steal-keplr.html](https://thehackernews.com/2026/11/web3auth-flaw-exploited-to-steal-keplr.html) |
| **Espionnage cyber — cibles gouvernementales, défense et télécoms en Asie du Sud** | Organisations d'Asie du Sud (secteurs gouvernemental, défense et télécoms) | Données de reconnaissance système et réseau (listes de répertoires, contenus de Desktop/Documents/Downloads, produits antivirus installés, lecteurs montés) ; captures d'écran ; accès distant persistant aux hôtes compromis ; documents bureautiques accessibles aux comptes compromis (risque d'exfiltration ultérieure). | Inconnu | [https://thehackernews.com/2026/11/bitter-hackers-deploy-new-paprat.html](https://thehackernews.com/2026/11/bitter-hackers-deploy-new-paprat.html) |
| **Santé (clinique orthopédique et de chirurgie reconstructrice)** | Southwest Orthopedic & Reconstructive Specialists (clinique, Oklahoma) | Revendiqué (non vérifié) : bases de données avec plus de 150 000 SSN associés à des noms et adresses de patients ; dossiers médicaux ; données de facturation ; adresses physiques. | 150000 | [https://www.yazoul.net/intel/claim/2026-11-10-southwest-ortho-ransomware-claim-by-interlock-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-10-southwest-ortho-ransomware-claim-by-interlock-nov-2026/?utm_source=mastodon&utm_medium=social) |
| **Secteur public / administration électronique** | Gouvernement de Moldavie (Agenția de Guvernare Electronică — services numériques de l'État) | Données d'état civil (nom, prénom, date et lieu de naissance, photographies, données des proches) ; permis de conduire, véhicules immatriculés, sociétés détenues ; données de santé et de protection sociale (assurance maladie, médecin de famille, prestations sociales, pensions, invalidité) ; données financières (IBAN, dettes fiscales, historique de paiements MPay) ; identifiants IDNP. | 750000 | [https://insicurezzadigitale.com/moldova-un-cittadino-su-tre-nelle-mani-degli-hacker-82-servizi-digitali-spenti-per-fermare-il-furto-di-dati/](https://insicurezzadigitale.com/moldova-un-cittadino-su-tre-nelle-mani-degli-hacker-82-servizi-digitali-spenti-per-fermare-il-furto-di-dati/) |
| **Gouvernement / affaires étrangères** | Antonio Tajani, ministre italien des Affaires étrangères (et proches) | Données personnelles du ministre et d'informations relatives à sa famille et à ses proches (nature exacte non précisée) ; informations confidentielles sur des responsables gouvernementaux proposées à la vente sur le dark web. | Inconnu | [https://www.securityweek.com/italys-meloni-blames-pro-russian-hackers-for-leak-of-foreign-ministers-data-on-the-dark-web/](https://www.securityweek.com/italys-meloni-blames-pro-russian-hackers-for-leak-of-foreign-ministers-data-on-the-dark-web/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-111497** | N/A | N/A | TRUE | Produits Apple (iOS, iPadOS, macOS, visionOS, watchOS) et Siemens SIMATIC (WinCC, PCS 7, etc.) | Dépassement de tampon (out-of-bounds write) dans le décodeur Brotli | Corruption de mémoire, déni de service ou exécution de code arbitraire selon le contexte d'exploitation. | Active | Appliquer les mises à jour Apple (iOS/iPadOS 27.2.1, macOS 27.2.1, etc.) et les correctifs Siemens disponibles. Pour les produits Siemens sans correctif, isoler les systèmes, restreindre les accès réseau et surveiller les entrées Brotli. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1495/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1495/)<br>[https://thehackernews.com/2026/11/apple-patches-imessage-group-chat.html](https://thehackernews.com/2026/11/apple-patches-imessage-group-chat.html)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113960** | N/A | N/A | FALSE | iMessage sur iOS, iPadOS, macOS et watchOS | Contournement d'autorisation | Atteinte à la confidentialité des conversations de groupe. | Theoretical | Mettre à jour vers iOS/iPadOS 27.2.1, macOS 27.2.1 et watchOS 27.2.1. Éviter les groupes iMessage avec des participants non fiables en attendant. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://thehackernews.com/2026/11/apple-patches-imessage-group-chat.html](https://thehackernews.com/2026/11/apple-patches-imessage-group-chat.html)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113961** | N/A | N/A | FALSE | iMessage sur iOS, iPadOS, macOS et watchOS | Contournement d'autorisation | Atteinte à la confidentialité des messages de groupe. | Theoretical | Mettre à jour vers iOS/iPadOS 27.2.1, macOS 27.2.1 et watchOS 27.2.1. Éviter les groupes iMessage avec des participants non fiables en attendant. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://thehackernews.com/2026/11/apple-patches-imessage-group-chat.html](https://thehackernews.com/2026/11/apple-patches-imessage-group-chat.html)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113963** | N/A | N/A | FALSE | Produits Apple (iOS, iPadOS, macOS, watchOS, visionOS) | Exposition d'informations | Exposition de données sensibles. | Theoretical | Appliquer les mises à jour Apple (iOS/iPadOS 27.2.1, macOS 27.2.1, etc.). | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113964** | N/A | N/A | FALSE | Apple iOS/iPadOS (27.2.1, 26.7.3, 18.7.12), macOS Golden Gate 27.2.1, Tahoe 26.7.3, Sequoia 15.8.3, watchOS 27.2.1 et 26.6.1, visionOS 27.2.1 — bulletin de novembre 2026 couvrant neuf CVE | Multiples : contournement de limitation de tentatives d'appairage Bluetooth/AirPlay, appairage sans interaction, corruption mémoire, accès à des données sensibles, fuite de messages iMessage | Affaiblissement du processus d'appairage Bluetooth et AirPlay (appairage non authentifié, sans interaction), corruption mémoire exploitable, accès à des messages de groupe iMessage non destinés à l'utilisateur et divulgation de données utilisateur sensibles. L'impact est particulièrement critique sur les appareils mobiles utilisés pour l'accès aux messageries et aux données d'entreprise. | Theoretical | Mettre à jour vers iOS/iPadOS 27.2.1, 26.7.3 ou 18.7.12 ; macOS Golden Gate 27.2.1, Tahoe 26.7.3, Sequoia 15.8.3 ; watchOS 27.2.1 ou 26.6.1 ; visionOS 27.2.1. Ne pas supposer que les mises à jour automatiques se sont appliquées : vérifier chaque appareil via MDM. Fixer une date de remplacement pour le matériel ne pouvant pas exécuter les versions corrigées, et restreindre l'appairage Bluetooth/AirPlay aux périphériques approuvés en attendant. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129)<br>[https://isc.sans.edu/diary/rss/33506](https://isc.sans.edu/diary/rss/33506) |
| **CVE-2026-113965** | N/A | N/A | FALSE | Produits Apple (iOS, iPadOS, macOS, watchOS, visionOS) | Contournement de la politique de sécurité | Appairage non autorisé. | Theoretical | Mettre à jour les appareils Apple. Désactiver Bluetooth lorsqu'il n'est pas nécessaire. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113968** | N/A | N/A | FALSE | Produits Apple (iOS, iPadOS, macOS, watchOS, visionOS) | Contournement de la politique de sécurité | Contournement de la politique de sécurité Bluetooth. | Theoretical | Mettre à jour les appareils Apple. Désactiver Bluetooth lorsqu'il n'est pas nécessaire. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113969** | N/A | N/A | FALSE | Produits Apple (iOS, iPadOS, macOS, watchOS, visionOS) | Contournement de la politique de sécurité | Appairage AirPlay non autorisé. | Theoretical | Mettre à jour les appareils Apple. Restreindre l'utilisation d'AirPlay aux réseaux de confiance. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113970** | N/A | N/A | FALSE | Produits Apple (iOS, iPadOS, macOS, watchOS, visionOS) | Corruption de mémoire | Corruption de mémoire, déni de service ou exécution de code. | Theoretical | Mettre à jour les appareils Apple. Désactiver Bluetooth lorsqu'il n'est pas nécessaire. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-113971** | N/A | N/A | FALSE | Produits Apple (iOS, iPadOS, macOS, watchOS, visionOS) | Contournement de la politique de sécurité | Contournement de la politique de sécurité AirPlay. | Theoretical | Mettre à jour les appareils Apple. Désactiver AirPlay sur l'écran verrouillé. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1487/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-129) |
| **CVE-2026-121068** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-121076** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-121095** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-121184** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-121208** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-121213** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-121233** | N/A | N/A | FALSE | Google Chrome | Non spécifié | Non spécifié par l'éditeur ; pourrait permettre une exécution de code ou un déni de service. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. Appliquer également les correctifs aux navigateurs Chromium. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/) |
| **CVE-2026-125342** | N/A | N/A | FALSE | Google Chrome | Ressource non initialisée dans GPU | Exécution de code arbitraire dans le contexte de l'utilisateur. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125343** | N/A | N/A | FALSE | Google Chrome | Dépassement de tampon dans Compositing | Exécution de code arbitraire dans le contexte de l'utilisateur. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125344** | N/A | N/A | FALSE | Google Chrome | Confusion de type dans V8 | Exécution de code arbitraire dans le contexte de l'utilisateur. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125345** | N/A | N/A | FALSE | Google Chrome | Ressource non initialisée dans WebGL | Exécution de code arbitraire dans le contexte de l'utilisateur. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125346** | N/A | N/A | FALSE | Google Chrome | Use-after-free dans XML | Corruption de données, crash ou exécution de code arbitraire. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125347** | N/A | N/A | FALSE | Google Chrome | Autorisation incorrecte dans FileSystem | Contournement de sécurité et accès non autorisé à des ressources. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125348** | N/A | N/A | FALSE | Google Chrome | Écriture hors limites dans GPU | Exécution de code arbitraire dans le contexte de l'utilisateur. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125349** | N/A | N/A | FALSE | Google Chrome | Ressource non initialisée dans GPU | Exécution de code arbitraire dans le contexte de l'utilisateur. | Theoretical | Mettre à jour Chrome vers 157.0.8103.50/.51 et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127) |
| **CVE-2026-125350** | N/A | N/A | FALSE | Google Chrome (composant XML) — Chrome Stable 157.0.8103.50/.51 (Windows, macOS), 157.0.8103.50 (Linux) et Extended Stable 156.0.8078.96 ; navigateurs dérivés de Chromium (Microsoft Edge notamment) | Use-after-free (corruption mémoire) dans le composant XML — CWE-416 | Corruption mémoire exploitable dans le processus de rendu : déni de service (crash), corruption de données et, selon la technique d'exploitation, exécution de code arbitraire dans le contexte du navigateur. Un chaînage avec une faille d'évasion de sandbox permettrait une compromission complète du poste, avec vol de cookies/sessions, accès aux données applicatives et pivot vers les ressources internes accessibles depuis le navigateur. | Active | Mettre à jour immédiatement vers Chrome 157.0.8103.50/.51 (Windows/macOS) ou 157.0.8103.50 (Linux), et vers Extended Stable 156.0.8078.96 pour les parcs sur ce canal. Pousser la mise à jour des navigateurs Chromium tiers (Edge, Brave, Opera) et des images de navigateurs headless utilisées en CI. Vérifier l'inventaire des versions via la gestion de parc, forcer le redémarrage des navigateurs, et surveiller les processus enfants anormaux lancés par le navigateur en attendant une couverture détection complète. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1488/)<br>[https://thehackernews.com/2026/11/google-issues-chrome-security-update.html](https://thehackernews.com/2026/11/google-issues-chrome-security-update.html)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-127)<br>[https://krebsonsecurity.com/2026/11/microsoft-fixes-nearly-1100-security-vulnerabilities/](https://krebsonsecurity.com/2026/11/microsoft-fixes-nearly-1100-security-vulnerabilities/)<br>[https://securityaffairs.com/202772/breaking-news/google-fixes-the-eighth-actively-exploited-chrome-zero-day-of-2026.html](https://securityaffairs.com/202772/breaking-news/google-fixes-the-eighth-actively-exploited-chrome-zero-day-of-2026.html)<br>[https://socprime.com/blog/cve-2026-125350-chrome-xml-zero-day-exploited-in-the-wild/](https://socprime.com/blog/cve-2026-125350-chrome-xml-zero-day-exploited-in-the-wild/) |
| **CVE-2026-58114** | N/A | N/A | FALSE | Siemens SIMATIC (BATCH, PCS 7, WinCC, Process Historian, Information Server, etc.) | Exécution de code arbitraire à distance | Compromission de systèmes industriels, exécution de code et contournement de sécurité. | Theoretical | Appliquer les correctifs Siemens disponibles. Pour les produits sans correctif, isoler les réseaux OT, restreindre les accès et appliquer des mesures compensatoires. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1495/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1495/) |
| **CVE-2026-59082** | N/A | N/A | FALSE | Siemens SIMATIC WinCC V7.5, V8.0 et V8.1 | Contournement de la politique de sécurité | Contournement de sécurité sur les systèmes SCADA. | Theoretical | Appliquer les correctifs Siemens, segmenter le réseau OT et restreindre les accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1495/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1495/) |
| **CVE-2026-124194** | 6.5 | N/A | FALSE | Produits Microsoft (Azure, Defender, Exchange Server, Office, SQL Server, SharePoint Server, Windows) | Usurpation (spoofing) — CWE-356 : l'interface produit n'avertit pas l'utilisateur d'actions dangereuses | Divulgation d'un hash NTLMv2 permettant une attaque par relais (SMB, LDAP, HTTP) ou un cassage hors ligne du mot de passe, avec pour conséquence une usurpation d'identité, une élévation de privilèges et un mouvement latéral dans le domaine. L'impact direct sur la confidentialité est élevé (C:H) même si l'intégrité et la disponibilité ne sont pas affectées. | Active | Appliquer les mises à jour de sécurité du 10 novembre 2026 sur tous les builds Outlook/Office et Microsoft 365 Apps for Enterprise. En défense en profondeur : désactiver NTLMv1, imposer la signature SMB et LDAP, activer EPA, bloquer les sorties TCP 445/WebDAV vers Internet, filtrer les fichiers de message externes à la passerelle de messagerie et sensibiliser les utilisateurs à l'ouverture de pièces jointes inattendues. | [https://www.cisecurity.org/advisory/critical-patches-issued-for-microsoft-products-november-10-2026_2026-132](https://www.cisecurity.org/advisory/critical-patches-issued-for-microsoft-products-november-10-2026_2026-132)<br>[https://krebsonsecurity.com/2026/11/microsoft-fixes-nearly-1100-security-vulnerabilities/](https://krebsonsecurity.com/2026/11/microsoft-fixes-nearly-1100-security-vulnerabilities/)<br>[https://securityonline.info/november-2026-patch-tuesday/?utm_source=mastodon&utm_medium=jetpack_social](https://securityonline.info/november-2026-patch-tuesday/?utm_source=mastodon&utm_medium=jetpack_social)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194) |
| **CVE-2026-96437** | 8.2 | N/A | FALSE | Kong Gateway Enterprise — plugin ai-azure-content-safety | Contournement de contrôle de sécurité (fail-open) — CWE-636 | Neutralisation des garde-fous de sécurité IA : injection de prompts, génération de contenus interdits, contournement des politiques de conformité, et potentiellement exfiltration de données internes si le modèle a accès à des sources sensibles (RAG, connecteurs). L'atteinte à l'intégrité des sorties du modèle peut se propager aux applications consommatrices. | None | Mettre à jour le plugin ai-azure-content-safety et Kong Gateway Enterprise vers la dernière version (changelog sur developer[.]konghq[.]com). Configurer une taille de body buffer couvrant les requêtes légitimes et rejeter en amont, au niveau du reverse proxy ou du WAF, toute requête dépassant la limite inspectable. Journaliser les tailles de corps et les décisions du plugin, et tester le comportement après mise à jour. | [https://cvefeed.io/vuln/detail/CVE-2026-96437](https://cvefeed.io/vuln/detail/CVE-2026-96437) |
| **CVE-2026-92545** | 8.7 | N/A | FALSE | Kong Gateway Enterprise et Kong AI Gateway — plugins proxy-cache et proxy-cache-advanced | Utilisation d'un cache contenant des informations sensibles / collision de clé de cache — CWE-524 | Divulgation d'informations entre hôtes ou tenants : contenus applicatifs, données personnelles, éventuellement en-têtes ou jetons de session mis en cache. La contamination de réponses peut également induire des comportements erronés côté client et porter atteinte à la confiance dans la plateforme API. | None | Mettre à jour Kong Gateway Enterprise et Kong AI Gateway vers la dernière version (changelogs sur developer[.]konghq[.]com). Vérifier que la génération de la clé de cache inclut correctement le hostname, purger les caches existants et tester le comportement de cache après mise à jour. En attendant, désactiver les plugins de cache sur les routes sensibles ou cloisonner les caches par tenant. | [https://cvefeed.io/vuln/detail/CVE-2026-92545](https://cvefeed.io/vuln/detail/CVE-2026-92545) |
| **CVE-2026-92443** | 8.2 | N/A | FALSE | Kong Gateway Enterprise et Kong AI Gateway (plugins de cache) | Mauvais contrôle d'autorisation dans la mise en cache (CWE-524) | Divulgation d'informations sensibles, contournement d'autorisation et accès non autorisé à des ressources protégées. | Theoretical | Appliquer le correctif éditeur pour Kong Gateway et Kong AI Gateway, vérifier les versions corrigées dans les changelogs, et s'assurer que les clés de cache incluent l'identité de l'appelant. | [https://cvefeed.io/vuln/detail/CVE-2026-92443](https://cvefeed.io/vuln/detail/CVE-2026-92443) |
| **CVE-2026-92442** | 8.3 | N/A | FALSE | Kong Gateway Enterprise (plugin graphql-proxy-cache-advanced) | Empoisonnement de cache avancé via omission de l'identité de l'appelant (CWE-524) | Divulgation d'informations, accès non autorisé à des données GraphQL et potentiel empoisonnement de cache. | Theoretical | Mettre à jour le plugin graphql-proxy-cache-advanced, appliquer le correctif Kong, redémarrer les services et vérifier que les clés de cache sont uniques par appelant. | [https://cvefeed.io/vuln/detail/CVE-2026-92442](https://cvefeed.io/vuln/detail/CVE-2026-92442) |
| **CVE-2026-123041** | 8.2 | N/A | FALSE | Kong Gateway Enterprise et Kong AI Gateway (plugin request-callout) | Empoisonnement de cache via omission d'en-têtes de callout (CWE-524) | Divulgation d'informations sensibles, usurpation de contexte et accès non autorisé à des réponses de callout. | Theoretical | Mettre à jour Kong Gateway Enterprise, configurer la clé de cache pour inclure tous les en-têtes pertinents, et appliquer le correctif éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-123041](https://cvefeed.io/vuln/detail/CVE-2026-123041) |
| **CVE-2026-111760** | N/A | N/A | FALSE | Git (versions 2.50 à 2.56) et outils intégrant Git | Troncature d'entier dans l'index Git permettant l'exécution de code lors de clones récursifs | Exécution de code arbitraire sur la machine de la victime, compromission de la chaîne d'approvisionnement et accès non autorisé au système. | Theoretical | Mettre à jour vers Git 2.56.1 ou les versions corrigées (2.50.2, 2.51.3, 2.52.1, 2.53.1, 2.54.1, 2.55.1), mettre à jour les applications intégrant Git, et éviter les clones récursifs de dépôts non fiables. | [https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html)<br>[https://securityonline.info/git-security-vulnerabilities-cve-2026-111760-patched/?utm_source=mastodon&utm_medium=jetpack_social](https://securityonline.info/git-security-vulnerabilities-cve-2026-111760-patched/?utm_source=mastodon&utm_medium=jetpack_social)<br>[https://infosec.exchange/@DailyCyberSecurity/117594669710587397](https://infosec.exchange/@DailyCyberSecurity/117594669710587397)<br>[https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/](https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/)<br>[https://infosec.exchange/@cyberseckyle/117594419753574151](https://infosec.exchange/@cyberseckyle/117594419753574151) |
| **CVE-2026-113408** | N/A | N/A | FALSE | Git (protocole v2, backend de références files) | Traversée de chemin via symref HEAD non validé | Écriture de fichiers hors du répertoire prévu, corruption de dépôt et potentielle exécution de code via des références malveillantes. | Theoretical | Mettre à jour vers Git 2.56.1 ou les versions corrigées, et éviter de cloner des dépôts vides depuis des serveurs non fiables. | [https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html) |
| **CVE-2026-114467** | N/A | N/A | FALSE | Git (gestion des signatures GPG) | Corruption de pile lors de la suppression de signatures GPG | Déni de service, corruption de mémoire et instabilité des services d'hébergement qui effectuent des merges pour les utilisateurs. | Theoretical | Mettre à jour vers Git 2.56.1 ou les versions corrigées, et limiter les merges de tags non fiables. | [https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html)<br>[https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/](https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/)<br>[https://infosec.exchange/@cyberseckyle/117594419753574151](https://infosec.exchange/@cyberseckyle/117594419753574151) |
| **CVE-2026-114469** | N/A | N/A | FALSE | Git (application de patches binaires) | Lecture hors limites via un patch binaire surdimensionné | Déni de service et crash de Git lors du traitement de patches binaires malveillants. | Theoretical | Mettre à jour vers Git 2.56.1 ou les versions corrigées, et éviter de traiter des patches binaires provenant de sources non fiables. | [https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html) |
| **CVE-2026-105437** | N/A | N/A | FALSE | Git (machinerie de merge) et services d'hébergement | Corruption de tas lors de grands merges | Corruption de mémoire, exécution de code potentielle et déni de service sur les serveurs de code. | Theoretical | Mettre à jour vers Git 2.56.1 ou les versions corrigées, et restreindre les merges de contenu non fiable. | [https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html)<br>[https://securityonline.info/git-security-vulnerabilities-cve-2026-111760-patched/?utm_source=mastodon&utm_medium=jetpack_social](https://securityonline.info/git-security-vulnerabilities-cve-2026-111760-patched/?utm_source=mastodon&utm_medium=jetpack_social)<br>[https://infosec.exchange/@DailyCyberSecurity/117594669710587397](https://infosec.exchange/@DailyCyberSecurity/117594669710587397)<br>[https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/](https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/)<br>[https://infosec.exchange/@cyberseckyle/117594419753574151](https://infosec.exchange/@cyberseckyle/117594419753574151) |
| **CVE-2026-114466** | N/A | N/A | FALSE | Git (git fast-import) | Accès au système de fichiers via des flux fast-import | Lecture de fichiers arbitraires, écriture de fichiers et potentielle compromission du système. | Theoretical | Mettre à jour vers Git 2.56.1 ou les versions corrigées, et ne pas traiter de flux fast-import non fiables. | [https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html)<br>[https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/](https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/)<br>[https://infosec.exchange/@cyberseckyle/117594419753574151](https://infosec.exchange/@cyberseckyle/117594419753574151) |
| **CVE-2026-123218** | 9.8 | N/A | TRUE | IBM Aspera Faspex 5.0.0 à 5.0.19 | Contournement d'autorisation permettant l'obtention de privilèges administrateur (CWE-863) | Prise de contrôle administrative de la plateforme de transfert de fichiers, avec risque d'accès, de modification ou d'exfiltration des données échangées. | Active | Appliquer IBM Aspera Faspex 5.0.19 PL1 sans délai. En l'absence de workaround, restreindre l'exposition réseau du service et surveiller les actions administratives. | [https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html](https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html)<br>[https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/](https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/) |
| **CVE-2026-116779** | 9.8 | N/A | TRUE | FreeSWITCH (versions antérieures à 1.11.3) | Injection de code via des requêtes SIP MESSAGE | Exécution de code arbitraire sur le serveur de téléphonie, avec risque de compromission complète, de fraude téléphonique et de pivot vers le réseau interne. | Active | Mettre à jour vers FreeSWITCH 1.11.3. Restreindre l'exposition SIP, filtrer les messages SIP MESSAGE et limiter l'accès à l'API de contrôle aux réseaux d'administration. | [https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html](https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html)<br>[https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/](https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/) |
| **CVE-2026-123158** | 8.1 | N/A | TRUE | OpenSSH sur systèmes Linux utilisant musl libc (Alpine par défaut, OpenWrt, Buildroot, Yocto), avec PAM désactivé et PasswordAuthentication activé | Contournement d'authentification via code de retour inattendu (SSHole) | Prise de contrôle à distance d'hôtes SSH exposés : reconnaissance, requêtes vers les métadonnées cloud, lecture des hachages et des clés SSH root, modification des authorized_keys, et dans certains cas déploiement d'un implant Python nommé TAC Agent. Des activités de botnet et de minage ont également été rapportées. | Active | Mettre à jour vers OpenSSH 10.6p2 (5 novembre 2026) ou appliquer le backport de la distribution, puis redémarrer sshd. Mesure temporaire : désactiver PasswordAuthentication après vérification des accès par clé. Restreindre l'exposition SSH, surveiller les authentifications par mot de passe et rechercher les artefacts de persistance (authorized_keys, /opt/py3/tac_agent.py, /etc/init.d/tac-agent). | [https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html](https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html)<br>[https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/](https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/) |
| **CVE-2026-102895** | 9.8 | N/A | TRUE | GPUStack (versions antérieures à 2.2.0) | Authentification incorrecte permettant un accès administratif non authentifié | Prise de contrôle administrative de la plateforme d'infrastructure IA : accès aux modèles, aux jeux de données, aux clés d'API et aux nœuds de calcul gérés par GPUStack. | Active | Mettre à jour vers GPUStack 2.2.0. En attendant, restreindre l'exposition réseau de l'interface d'administration et surveiller les actions administratives non authentifiées. | [https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html](https://thehackernews.com/2026/11/cisa-warns-of-active-exploitation-of.html)<br>[https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/](https://www.reddit.com/r/blueteamsec/comments/1xsguwn/cisa_added_openssh_sshole_and_three_other_flaws/) |
| **CVE-2026-125298** | 9.8 | N/A | FALSE | AsiaInfo Business Support System (BSS) 9.2.0 à 9.2.40 | Vérification impropre de signature cryptographique (CWE-347) | Exécution d'actions administratives non autorisées, avec risque de compromission complète du système de support opérateur et d'accès aux données clients. | None | Mettre à jour vers AsiaInfo BSS 9.2.41, vérifier la configuration de validation des signatures JWT, invalider les jetons existants et surveiller les actions privilégiées. | [https://cvefeed.io/vuln/detail/CVE-2026-125298](https://cvefeed.io/vuln/detail/CVE-2026-125298) |
| **CVE-2026-125297** | 9.8 | N/A | FALSE | AsiaInfo Business Support System (BSS) 9.2.0 à 9.2.40 | Absence d'authentification pour une fonction critique (CWE-306) / absence d'autorisation (CWE-862) | Création de comptes administrateurs non autorisés et prise de contrôle de comptes existants, menant à une compromission complète du BSS. | None | Mettre à jour vers AsiaInfo BSS 9.2.41, restreindre l'accès à l'API de management et auditer les comptes à privilèges. | [https://cvefeed.io/vuln/detail/CVE-2026-125297](https://cvefeed.io/vuln/detail/CVE-2026-125297) |
| **CVE-2026-122102** | 8.7 | N/A | FALSE | Adobe Connect 12.12 et versions antérieures (Windows) | Cross-site scripting stocké (CWE-79) | Vol de session ou prise de contrôle du compte de la victime, avec possibilité d'accès élevé aux ressources de réunion et aux données partagées. | None | Appliquer le correctif Adobe APSB26-191, assainir les entrées utilisateur, mettre en place un encodage de sortie et une CSP, et éviter les champs de formulaire non corrigés. | [https://cvefeed.io/vuln/detail/CVE-2026-122102](https://cvefeed.io/vuln/detail/CVE-2026-122102)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-adobe-products-could-allow-for-arbitrary-code-execution_2026-130](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-adobe-products-could-allow-for-arbitrary-code-execution_2026-130) |
| **CVE-2026-121841** | N/A | N/A | FALSE | Firefox pour iOS versions antérieures à 160.0 | Élévation de privilèges | Élévation de privilèges sur le terminal mobile, avec risque d'accès non autorisé aux données de l'application et du système. | None | Mettre à jour Firefox pour iOS vers 160.0 ou supérieur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1490/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1490/) |
| **CVE-2026-121842** | N/A | N/A | FALSE | Firefox pour iOS versions antérieures à 160.0 | Élévation de privilèges | Élévation de privilèges sur le terminal mobile, avec risque d'accès non autorisé aux données. | None | Mettre à jour Firefox pour iOS vers 160.0 ou supérieur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1490/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1490/) |
| **CVE-2026-121843** | N/A | N/A | FALSE | Firefox pour iOS versions antérieures à 160.0 | Élévation de privilèges / problème de sécurité non spécifié | Élévation de privilèges sur le terminal mobile, avec risque d'accès non autorisé aux données. | None | Mettre à jour Firefox pour iOS vers 160.0 ou supérieur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1490/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1490/) |
| **CVE-2026-90436** | N/A | N/A | FALSE | Atlassian Confluence Data Center, versions antérieures à 9.2.28 | Exécution de code arbitraire à distance (RCE) | Un attaquant non authentifié ou faiblement privilégié pourrait exécuter du code arbitraire sur le serveur Confluence, aboutissant à la compromission complète de l'instance, à l'accès aux espaces documentaires et aux secrets applicatifs, voire à un pivot vers le système d'information interne. | None | Appliquer sans délai la mise à jour vers Confluence Data Center 9.2.28 ou supérieure conformément au bulletin Atlassian. En attendant, restreindre l'accès réseau à l'instance, filtrer les URI sensibles au niveau du reverse proxy/WAF, surveiller les journaux d'accès et rechercher des artefacts de persistance (webshells, plugins non autorisés). | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1492/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1492/)<br>[https://confluence.atlassian.com/security/cve-2026-90436-remote-code-execution-in-confluence-data-center-1874560038.html](https://confluence.atlassian.com/security/cve-2026-90436-remote-code-execution-in-confluence-data-center-1874560038.html) |
| **CVE-2026-124993** | N/A | N/A | FALSE | Synology DSM : 7.2.1-x < 7.2.1-69057-13, 7.2.2-x < 7.2.2-72806-10, 7.3.x < 7.3.2-86009-5, 7.4.x < 7.4.1-90080-1 | Multiples vulnérabilités : déni de service à distance, atteinte à la confidentialité, contournement de politique de sécurité, SSRF | Exploitation possible pour provoquer l'indisponibilité des services DSM, utiliser le NAS comme rebond SSRF vers le réseau interne, contourner des contrôles de sécurité ou accéder à des données stockées sans autorisation. | None | Mettre à jour DSM vers les versions corrigées indiquées par Synology (7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, 7.4.1-90080-1 ou supérieures). Restreindre l'exposition d'administration DSM, désactiver les services non nécessaires, activer le pare-feu DSM et l'authentification à deux facteurs, et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1493/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1493/)<br>[https://www.synology.com/en-global/security/advisory/Synology_SA_26_18](https://www.synology.com/en-global/security/advisory/Synology_SA_26_18)<br>[https://www.synology.com/en-global/security/advisory/Synology_SA_26_19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19) |
| **CVE-2026-119055** | N/A | N/A | FALSE | Schneider Electric EcoStruxure Power Build Rapsody (packs BEL(EN), BEL(FR), ESP, FR, INT(EN), INT(FR), NL, PT) versions antérieures aux seuils corrigés | Exécution de code arbitraire | Exécution de code arbitraire sur le poste d'ingénierie de l'opérateur, avec un risque de vol de configurations, de modification des paramètres de protection électrique et de pivot vers les réseaux OT. | None | Appliquer les versions corrigées publiées par Schneider Electric pour chaque pack linguistique. En attendant, restreindre l'usage de l'outil aux postes cloisonnés, contrôler l'origine des fichiers de projet, analyser les fichiers entrants et surveiller les postes d'ingénierie. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1494/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1494/)<br>[https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-314-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-314-01.pdf](https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-314-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-314-01.pdf) |
| **CVE-2026-107496** | N/A | N/A | FALSE | OpenSSL : 1.0.2x < 1.0.2zt, 1.1.1x < 1.1.1zk, 3.0.x < 3.0.24, 3.5.x < 3.5.10, 4.0.x < 4.0.4, 4.1.x < 4.1.1 | Multiples vulnérabilités : déni de service à distance, atteinte à la confidentialité, contournement de politique de sécurité | Indisponibilité de services TLS critiques, fuite d'informations sensibles et possibilité de contourner des contrôles de sécurité reposant sur TLS, avec un risque d'interception ou de dégradation de la confidentialité des échanges. | None | Mettre à jour OpenSSL vers les versions corrigées (1.0.2zt, 1.1.1zk, 3.0.24, 3.5.10, 4.0.4, 4.1.1) et redémarrer les services dépendants. Vérifier également les bibliothèques embarquées dans les appliances et conteneurs, et filtrer les sources générant des handshakes malveillants. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1496/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1496/)<br>[https://openssl-library.org/news/secadv/20261110.txt](https://openssl-library.org/news/secadv/20261110.txt) |
| **CVE-2026-126261** | 9.8 | N/A | FALSE | Fortinet FortiManager 8.0.0, 7.6.0 à 7.6.7, 7.4.0 à 7.4.5, 7.2.0 à 7.2.8 | Autorisation incorrecte (CWE-285) permettant l'exécution de code ou de commandes non authentifiée | Exécution de code arbitraire sur le gestionnaire central, avec possibilité de modification des politiques de sécurité, de désactivation de protections, de vol de secrets et de pivot vers l'ensemble des équipements FortiGate administrés. | Theoretical | Mettre à jour FortiManager vers une version corrigée selon FG-IR-26-275 et restreindre immédiatement l'accès au port FGFM aux seules sources légitimes. Auditer les configurations poussées vers les FortiGate et surveiller les connexions FGFM inhabituelles. | [https://cvefeed.io/vuln/detail/CVE-2026-126261](https://cvefeed.io/vuln/detail/CVE-2026-126261)<br>[https://fortiguard.fortinet.com/psirt/FG-IR-26-275](https://fortiguard.fortinet.com/psirt/FG-IR-26-275) |
| **CVE-2026-91000** | 8.4 | N/A | FALSE | N-able N-central versions antérieures à 2026.4.1 | Authentification manquante pour une fonction critique (CWE-306) via canaux IPC non sécurisés, entraînant une élévation de privilèges locale | Élévation de privilèges locale sur le serveur N-central, avec possibilité de compromettre les agents gérés, d'exécuter des commandes sur les endpoints du parc et d'accéder aux identifiants stockés. | None | Mettre à jour N-central vers la version 2026.4.1 ou supérieure. Restreindre et journaliser les accès locaux au serveur, appliquer le principe du moindre privilège et surveiller les élévations de privilèges anormales. | [https://cvefeed.io/vuln/detail/CVE-2026-91000](https://cvefeed.io/vuln/detail/CVE-2026-91000)<br>[https://me.n-able.com/s/security-advisory/aArVy0000002irNKAQ/cve202691000-insecure-ipc-channels-lead-to-local-privilege-escalation](https://me.n-able.com/s/security-advisory/aArVy0000002irNKAQ/cve202691000-insecure-ipc-channels-lead-to-local-privilege-escalation) |
| **CVE-2026-89324** | 9.8 | N/A | FALSE | Plugin Basel Post Types pour WordPress, versions <= 1.18 (avec WooCommerce actif et un fournisseur de social login Basel configuré) | Contournement d'authentification (CWE-287) via signature de callback Opauth forgée et sel de secours codé en dur | Prise de contrôle complète de sites WordPress : usurpation d'identité de n'importe quel compte, y compris administrateur, contournement du mot de passe et de la MFA, obtention d'un cookie de session authentifié, puis installation de plugins malveillants, exfiltration de données clients et défiguration. | Theoretical | Mettre à jour le plugin Basel Post Types vers une version corrigée. En attendant, désactiver le social login Basel ou le plugin, révoquer les sessions, réinitialiser les mots de passe administrateur et faire tourner les salts WordPress ainsi que les secrets OAuth. | [https://cvefeed.io/vuln/detail/CVE-2026-89324](https://cvefeed.io/vuln/detail/CVE-2026-89324)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/40a04176-cec2-4723-a5c6-23ca2ea6ef97?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/40a04176-cec2-4723-a5c6-23ca2ea6ef97?source=cve) |
| **CVE-2026-82391** | 9.1 | N/A | FALSE | Serveur HTTP/2 de Zephyr, gestionnaire de fichiers statiques (subsys/net/lib/http/http_server_http2.c) | Écriture hors limites (out-of-bounds write) via longueur de buffer de réception corrompue | Corruption mémoire à distance dans l'espace d'adressage unique du serveur, pouvant provoquer un crash ou un blocage du dispositif, et plausiblement une exécution de code via l'écrasement de pointeurs et de tables de fonctions. | Theoretical | Appliquer le correctif qui utilise une variable locale size_t file_size dans le gestionnaire HTTP/2, puis reconstruire l'application. Désactiver HTTP/2 ou le système de fichiers statique si non nécessaire et restreindre l'exposition réseau du serveur embarqué. | [https://cvefeed.io/vuln/detail/CVE-2026-82391](https://cvefeed.io/vuln/detail/CVE-2026-82391) |
| **CVE-2026-77685** | 8.3 | N/A | FALSE | Pile Bluetooth Classic RFCOMM de Zephyr (subsys/bluetooth/host/classic/rfcomm.c) | Sous-dépassement d'entier (integer underflow) menant à lecture et écriture hors limites | Fuite d'environ 255 octets de mémoire adjacente vers l'attaquant et corruption mémoire du host Bluetooth, pouvant provoquer un crash. Les builds GOEP avec seulement le premier correctif restent vulnérables à une écriture hors limites résiduelle. | Theoretical | Appliquer les deux correctifs RFCOMM et mettre à jour les firmwares concernés. Désactiver RFCOMM si non nécessaire, limiter la connectabilité Bluetooth et surveiller les trames RFCOMM anormales. | [https://cvefeed.io/vuln/detail/CVE-2026-77685](https://cvefeed.io/vuln/detail/CVE-2026-77685) |
| **CVE-2026-126186** | 8.8 | N/A | FALSE | Active Storage de Ruby on Rails, traitement vidéo/audio/image via ffprobe, ffmpeg et ImageMagick | Lecture arbitraire de fichiers et exécution de code à distance via extension de fichier contrôlée (CWE-646) | Lecture de fichiers accessibles au processus applicatif via l'image de preview, chargement de bibliothèque native et possible exécution de code à distance dans le processus FFmpeg. Les applications acceptant des uploads non fiables et traitant des médias sont exposées. | Theoretical | Mettre à jour Active Storage vers 8.1.4.1 ou 8.0.5.2. Valider strictement les types de contenu, désactiver AviSynth, restreindre les délégués ImageMagick et exécuter les traitements médias dans un environnement sandboxé à privilèges minimaux. | [https://cvefeed.io/vuln/detail/CVE-2026-126186](https://cvefeed.io/vuln/detail/CVE-2026-126186) |
| **CVE-2026-125883** | 9.3 | N/A | FALSE | N-able N-central | XXE et empoisonnement de schéma XML (CWE-611) | Atteinte à la confidentialité et à l'intégrité des données, avec possibilité de lecture de fichiers, d'accès à des ressources internes et de perturbation du service. Le score CVSS 4.0 de 9,3 indique un impact critique. | Theoretical | Mettre à jour N-central vers 26.4.1 ou ultérieur. Désactiver la validation de schéma XML si non requise, valider strictement les entrées XML et configurer les parseurs pour interdire les entités externes. | [https://cvefeed.io/vuln/detail/CVE-2026-125883](https://cvefeed.io/vuln/detail/CVE-2026-125883) |
| **CVE-2026-125882** | 8.6 | N/A | FALSE | N-able N-central, fonctionnalité d'upload du dépôt de fichiers | Traversée de chemin relative (CWE-23) via upload dans le dépôt de fichiers | Écriture arbitraire de fichiers, pouvant conduire à une exécution de code à distance, à une persistance ou à la compromission de l'instance N-central. L'impact sur la confidentialité et l'intégrité est élevé. | Theoretical | Mettre à jour N-central vers 26.4.1 ou ultérieur. Restreindre les privilèges d'upload, valider les chemins de destination et surveiller les écritures hors répertoires autorisés. | [https://cvefeed.io/vuln/detail/CVE-2026-125882](https://cvefeed.io/vuln/detail/CVE-2026-125882) |
| **CVE-2026-125881** | 9.3 | N/A | FALSE | N-able N-central, fonctionnalité d'import de service et validation de schéma | Server-Side Request Forgery (SSRF) via validation de schéma à l'import de service (CWE-918) | Accès à des services internes, à des interfaces d'administration ou à des métadonnées cloud, avec atteinte à la confidentialité et à l'intégrité. Le score CVSS 4.0 de 9,3 indique un impact critique. | Theoretical | Mettre à jour N-central vers 26.4.1 ou ultérieur. Restreindre les connexions sortantes, bloquer les services de métadonnées et valider strictement les URL et schémas importés. | [https://cvefeed.io/vuln/detail/CVE-2026-125881](https://cvefeed.io/vuln/detail/CVE-2026-125881) |
| **CVE-2026-125880** | 8.3 | N/A | FALSE | N-able N-central, métadonnées de patch MMS3 | XSS stockée via neutralisation incorrecte des en-têtes HTTP (CWE-644) | Vol de session administrateur, exécution d'actions au nom de l'administrateur, accès à des données sensibles et modification de configuration. Le score CVSS 4.0 de 8,3 indique un impact élevé. | Theoretical | Mettre à jour N-central vers 26.4.1 ou ultérieur. Assainir les métadonnées de patch, renforcer les en-têtes de sécurité HTTP et déployer une politique CSP restrictive. | [https://cvefeed.io/vuln/detail/CVE-2026-125880](https://cvefeed.io/vuln/detail/CVE-2026-125880) |
| **CVE-2026-125879** | 8.6 | N/A | FALSE | N-able N-central, configuration syslog-ng accessible au compte nable | Attribution incorrecte de privilèges (CWE-266) menant à une élévation de privilèges locale | Compromission totale de l'hôte N-central avec privilèges root, permettant la persistance, la modification de configuration et l'accès aux données sensibles. Le score CVSS 4.0 de 8,6 indique un impact élevé. | Theoretical | Mettre à jour N-central vers 26.4.1 ou ultérieur. Restreindre les permissions d'écriture sur les fichiers de configuration syslog-ng et appliquer le moindre privilège aux comptes de service. | [https://cvefeed.io/vuln/detail/CVE-2026-125879](https://cvefeed.io/vuln/detail/CVE-2026-125879) |
| **CVE-2026-125878** | 8.7 | N/A | FALSE | N-able N-central | Injection OGNL / injection de ressource (CWE-79) | Un attaquant pourrait injecter des expressions OGNL et, selon l'avis N-able, aboutir à une exécution de code à distance sur le serveur N-central, compromettant l'infrastructure de supervision. | Theoretical | Mettre à jour N-able N-central vers la version 26.4.1 ou ultérieure. Restreindre l'exposition Internet de l'interface, surveiller les journaux web et appliquer les recommandations de l'avis de sécurité N-able. | [https://cvefeed.io/vuln/detail/CVE-2026-125878](https://cvefeed.io/vuln/detail/CVE-2026-125878) |
| **CVE-2026-105133** | N/A | N/A | FALSE | AhsayCBS | Chaîne d'exploitation : contournement d'authentification et exécution de commandes arbitraires | Compromission de serveurs de sauvegarde, dépôt de webshells JSP, minage XMRig, installation d'une backdoor Python, tunneling, accès distant et vol potentiel d'identifiants Veeam. | Active | Appliquer les correctifs AhsayCBS de mi-octobre 2026, isoler les serveurs de sauvegarde, supprimer les webshells, bloquer creepexplosiondarknight[.]com, retirer les exclusions Defender et révoquer les identifiants exposés. | [https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html](https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html) |
| **CVE-2026-105134** | N/A | N/A | FALSE | AhsayCBS | Chaîne d'exploitation : contournement d'authentification et exécution de commandes arbitraires | Compromission de serveurs de sauvegarde, dépôt de webshells JSP, minage XMRig, installation d'une backdoor Python, tunneling, accès distant et vol potentiel d'identifiants Veeam. | Active | Appliquer les correctifs AhsayCBS de mi-octobre 2026, isoler les serveurs de sauvegarde, supprimer les webshells, bloquer creepexplosiondarknight[.]com, retirer les exclusions Defender et révoquer les identifiants exposés. | [https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html](https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html) |
| **CVE-2026-76964** | 10.0 | N/A | FALSE | SAP NetWeaver AS ABAP (Internet Communication Manager - ICM) | Corruption mémoire dans le traitement des WebSocket fragmentés menant à une exécution de code à distance | Compromission complète du système SAP, exécution de commandes OS avec le compte <sid>adm et possibilité de mouvement latéral. | Theoretical | Appliquer la note SAP 3778530, mettre à jour les noyaux concernés, restreindre l'accès réseau à l'ICM et surveiller les journaux WebSocket. | [https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html](https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html) |
| **CVE-2026-89126** | 10.0 | N/A | FALSE | SAP Web Dispatcher | Corruption mémoire dans le traitement des WebSocket fragmentés menant à une exécution de code à distance | Exécution de code à distance sur le Web Dispatcher, interruption de service et compromission des systèmes SAP en aval. | Theoretical | Appliquer la note SAP 3778556, mettre à jour les noyaux concernés, restreindre l'accès réseau et surveiller les crashs ou redémarrages anormaux. | [https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html](https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html) |
| **CVE-2026-89103** | 10.0 | N/A | FALSE | SAP Gateway | Usurpation de serveur / contournement de contrôle d'accès | Actions non autorisées sur le système SAP, usurpation de serveur et possibilité de mouvement latéral. | Theoretical | Appliquer la note SAP 3798345, mettre à jour les noyaux concernés, restreindre les communications Gateway et surveiller les appels inhabituels. | [https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html](https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html) |
| **CVE-2026-120017** | 10.0 | N/A | FALSE | SAP NetWeaver AS ABAP et ABAP Platform (fournisseur de services SAML 2.0) | Contournement d'authentification SAML | Accès en tant qu'utilisateur privilégié, compromission complète du système SAP et accès aux systèmes connectés. | Theoretical | Appliquer la note SAP 3849308, vérifier les configurations SAML, révoquer les sessions actives et surveiller les authentifications privilégiées. | [https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html](https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html) |
| **CVE-2026-44748** | N/A | N/A | FALSE | SAP NetWeaver AS ABAP / fournisseur de services SAML 2.0 | Contournement d'authentification SAML | Accès avec un compte utilisateur normal, selon la source, avec un risque d'élévation ou d'actions non autorisées selon les privilèges du compte. | Theoretical | Vérifier l'application du correctif de juin 2026, revoir les configurations SAML et surveiller les authentifications anormales. | [https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html](https://thehackernews.com/2026/11/sap-patches-four-cvss-100-flaws.html) |
| **CVE-2026-88806** | 8.8 | N/A | FALSE | X.Org Server (libX11) | Débordement de tampon basé sur le tas menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte du processus client X11, compromission de la session utilisateur. | Theoretical | Appliquer la mise à jour libX11 référencée dans le merge request 309 et éviter de se connecter à des serveurs X11 non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-906/](http://www.zerodayinitiative.com/advisories/ZDI-26-906/) |
| **CVE-2026-88807** | 8.8 | N/A | FALSE | X.Org Server (libXrender) | Débordement de tampon basé sur le tas menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte du processus client X11, compromission de la session utilisateur. | Theoretical | Appliquer la mise à jour libXrender référencée dans le merge request 19 et éviter de se connecter à des serveurs X11 non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-905/](http://www.zerodayinitiative.com/advisories/ZDI-26-905/) |
| **CVE-2026-65110** | 7.8 | N/A | FALSE | NVIDIA Megatron-LM | Désérialisation de données non fiables menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte du processus, compromission de l'environnement d'entraînement ML. | Theoretical | Mettre à jour Megatron-LM vers 0.17.1 et ne charger que des checkpoints provenant de sources de confiance. | [http://www.zerodayinitiative.com/advisories/ZDI-26-904/](http://www.zerodayinitiative.com/advisories/ZDI-26-904/) |
| **CVE-2026-50256** | 7.8 | N/A | FALSE | X.Org Server | Débordement de tampon basé sur le tas menant à une élévation de privilèges | Élévation de privilèges vers root et compromission locale du système. | Theoretical | Appliquer le commit de correctif bb5158f962dc935e58ef8b4b5fcb31be201a6e07 et limiter l'accès local aux services X11. | [http://www.zerodayinitiative.com/advisories/ZDI-26-903/](http://www.zerodayinitiative.com/advisories/ZDI-26-903/) |
| **CVE-2026-50258** | 7.8 | N/A | FALSE | X.Org Server | Débordement d'entier menant à une élévation de privilèges | Élévation de privilèges vers root et compromission locale du système. | Theoretical | Appliquer le commit de correctif 543e108516428fc8c3bea91d6563ad266f9a801e et limiter l'accès local aux services X11. | [http://www.zerodayinitiative.com/advisories/ZDI-26-902/](http://www.zerodayinitiative.com/advisories/ZDI-26-902/) |
| **CVE-2026-50264** | 7.8 | N/A | FALSE | X.Org Server — fonction do_get_buffers (extension DRI2, ProcDRI2GetBuffers) | Débordement de tampon basé sur le tas (CWE-122) par validation insuffisante de la longueur des données fournies par l'utilisateur | Élévation de privilèges vers root et exécution de code arbitraire dans le contexte du serveur X, donc avec les droits du compte qui exécute Xorg (souvent root sur les configurations historiques). Compromission complète de l'hôte, accès aux secrets des sessions utilisateurs et possibilité de persistance. | Theoretical | Appliquer les correctifs des commits 339c2795 et b7aa65cc (mise à jour du paquet xserver de la distribution). En attendant, restreindre l'accès local aux sessions X, éviter les configurations Xorg s'exécutant en root, désactiver DRI2 si non nécessaire et surveiller les crashs du serveur X. | [http://www.zerodayinitiative.com/advisories/ZDI-26-901/](http://www.zerodayinitiative.com/advisories/ZDI-26-901/)<br>`hxxp://www[.]zerodayinitiative[.]com/advisories/ZDI-26-901/` |
| **CVE-2026-125271** | N/A | N/A | FALSE | AWS API MCP Server (awslabs.aws-api-mcp-server) versions >= 0.2.13 et < 1.5.1 | Contournement de politique de sécurité par normalisation incorrecte des noms d'opération (CWE-178 / CWE-863) | Exécution d'opérations AWS non autorisées (lecture, modification, suppression de ressources, actions IAM) via un agent IA, avec les permissions du rôle porté par le serveur MCP. Risque de compromission de données cloud et de persistance par création d'identités. | None | Mettre à jour vers awslabs.aws-api-mcp-server 1.5.1 ou supérieur et patcher les forks. Aucun contournement n'existe hors mise à jour : en attendant, restreindre les permissions IAM du rôle MCP et désactiver les opérations sensibles. | [https://aws.amazon.com/security/security-bulletins/rss/2026-176-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-176-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-176-aws/` |
| **CVE-2026-124848** | N/A | N/A | FALSE | Kiro CLI (anciennement Amazon Q Developer CLI) versions >= 1.16.0 et < 2.27.0 sur macOS et Linux | Permissions par défaut incorrectes sur des fichiers sensibles (CWE-276), entraînant une divulgation d'information locale | Divulgation de secrets (clés AWS, jetons d'API, code source propriétaire) à d'autres utilisateurs locaux, avec un risque de pivot vers les comptes cloud et les dépôts de code de l'organisation. | None | Mettre à jour vers Kiro CLI 2.27.0 et lancer l'outil une fois pour corriger les permissions des fichiers existants. À défaut, exécuter chmod -R go-rwx ~/.kiro, définir umask 077 avant le lancement et restreindre ou supprimer ~/.aws/amazonq/.cli_bash_history. | [https://aws.amazon.com/security/security-bulletins/rss/2026-178-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-178-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-178-aws/` |
| **CVE-2026-126087** | N/A | N/A | FALSE | OpenJD Sessions for Python < 0.11.0 et AWS Deadline Cloud worker agent < 0.33.0 (flottes gérées par le client, Linux) | Chemin de recherche non fiable (CWE-426) permettant une exécution de code avec les privilèges du worker agent | Élévation de privilèges sur l'hôte de rendu, vol d'identifiants cloud (rôle de flotte, métadonnées d'instance) et franchissement des frontières entre files d'attente, avec un risque de mouvement latéral dans le compte AWS. | Theoretical | Mettre à jour openjd-sessions vers 0.11.0 et le worker agent Deadline Cloud vers 0.33.0 (qui embarque la version corrigée). Aucun paramétrage ne supprime la vulnérabilité : en attendant, restreindre deadline:CreateJob aux principaux de confiance et examiner CloudTrail pour toute activité inattendue des rôles de flotte et de file d'attente. | [https://aws.amazon.com/security/security-bulletins/rss/2026-177-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-177-aws/)<br>`hxxps://aws[.]amazon[.]com/security/security-bulletins/rss/2026-177-aws/` |
| **CVE-2026-124853** | N/A | N/A | FALSE | Mozilla Firefox < 160, Firefox ESR < 153.7 et Firefox ESR < 115.45 | Multiples vulnérabilités : use-after-free, dépassements de bornes, pointeurs invalides, évasions de sandbox et contournement de la same-origin policy | Exécution de code arbitraire avec les droits de l'utilisateur du navigateur ; selon les privilèges du compte, installation de programmes, modification ou suppression de données et création de comptes. Les postes à privilèges administratifs sont les plus exposés. | None | Mettre à jour Firefox vers 160 ou supérieur et Firefox ESR vers 153.7 / 115.45 ou supérieur. Activer les mises à jour automatiques, restreindre les extensions au catalogue validé et surveiller les navigations vers des domaines suspects. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-mozilla-products-could-allow-for-arbitrary-code-execution_2026-131](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-mozilla-products-could-allow-for-arbitrary-code-execution_2026-131)<br>`hxxps://www[.]cisecurity[.]org/advisory/multiple-vulnerabilities-in-mozilla-products-could-allow-for-arbitrary-code-execution_2026-131` |
| **CVE-2026-107154** | N/A | N/A | FALSE | SonicOS management interface | Défaut de validation de session | Accès non autorisé à l'interface de management et modification potentielle de la configuration. | None | Appliquer les mises à jour SonicOS, limiter l'exposition de l'interface de management et surveiller les sessions administratives. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-107155** | N/A | N/A | FALSE | SonicOS management interface | Politique cross-domain permissive | Accès non autorisé à des ressources protégées et modification potentielle de la configuration. | None | Appliquer les mises à jour SonicOS, restreindre les origines autorisées et limiter l'exposition de l'interface de management. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-19703** | N/A | N/A | FALSE | SonicOS virtual appliances | Hachage de mot de passe faible | Divulgation de credentials et accès limité à la configuration de la plateforme. | None | Appliquer les mises à jour SonicOS, limiter les accès locaux et renouveler les credentials de plateforme. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-19868** | N/A | N/A | TRUE | SonicOS SSLVPN service | Contournement de l'authentification SAML | Contournement de la MFA et accès non autorisé au réseau via le SSLVPN. | Active | Appliquer les correctifs SonicWall, vérifier les politiques SAML/MFA et surveiller les connexions SSLVPN. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-82308** | N/A | N/A | FALSE | SonicOS SSLVPN service | Débordement de tampon heap pré-authentification | Indisponibilité du service SSLVPN et perturbation des accès distants. | None | Appliquer les correctifs SonicWall, limiter l'exposition du SSLVPN et surveiller les crashs. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-77708** | N/A | N/A | FALSE | SonicOS TACACS+ authentication client | Débordement de tampon stack pré-authentification | Indisponibilité du service d'authentification et perturbation des accès administratifs. | None | Appliquer les correctifs SonicWall, restreindre l'accès TACACS+ et surveiller les crashs. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-77709** | N/A | N/A | FALSE | SonicOS TACACS+ authentication client | Débordement de tampon heap pré-authentification | Indisponibilité du service d'authentification et perturbation des accès administratifs. | None | Appliquer les correctifs SonicWall, restreindre l'accès TACACS+ et surveiller les crashs. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sonicwall-sonicos-could-allow-for-authentication-bypass_2026-126) |
| **CVE-2026-0257** | N/A | N/A | FALSE | Palo Alto Networks firewall software | Contournement d'authentification | Compromission du réseau victime et accès non autorisé aux systèmes protégés. | Active | Appliquer les correctifs Palo Alto Networks, restreindre l'exposition de l'interface d'administration et surveiller les activités Qilin. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2026-15409** | N/A | N/A | TRUE | SonicWall SMA1000 remote access gateways | Vulnérabilité exploitée pour accès non autorisé | Accès non autorisé aux passerelles d'accès distant et compromission potentielle du réseau. | Active | Appliquer les correctifs SonicWall, restreindre l'exposition des passerelles et surveiller les activités INC Ransom. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2026-15410** | N/A | N/A | TRUE | SonicWall SMA1000 remote access gateways | Vulnérabilité exploitée pour accès non autorisé | Accès non autorisé aux passerelles d'accès distant et compromission potentielle du réseau. | Active | Appliquer les correctifs SonicWall, restreindre l'exposition des passerelles et surveiller les activités INC Ransom. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2026-45659** | N/A | N/A | TRUE | Microsoft SharePoint Server | Exécution de code à distance | Exécution de code arbitraire sur le serveur SharePoint et compromission potentielle de l'application. | Active | Appliquer les correctifs Microsoft, limiter les privilèges des comptes SharePoint et surveiller les exécutions anormales. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2025-60710** | N/A | N/A | TRUE | Microsoft Windows | Élévation de privilèges locale | Élévation de privilèges sur le système local et accès à des ressources protégées. | Active | Appliquer les correctifs Microsoft, limiter les privilèges locaux et surveiller les élévations anormales. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2026-59310** | N/A | N/A | TRUE | VMware vCenter | Exécution de code à distance non authentifiée | Compromission de l'infrastructure de virtualisation et exécution de code arbitraire. | Active | Appliquer les correctifs VMware, restreindre l'accès à vCenter et surveiller les accès non authentifiés. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2025-14733** | N/A | N/A | TRUE | WatchGuard Firebox | Accès distant non authentifié | Accès non autorisé au pare-feu et compromission potentielle du réseau. | Active | Appliquer les correctifs WatchGuard, restreindre l'exposition des services et surveiller les accès distants. | [https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/](https://securelist.com/malware-report-q3-2026-pc-iot-statistics/121843/) |
| **CVE-2026-111560** | N/A | N/A | TRUE | Barracuda Networks Email Security Gateway, Load Balancer, Application Delivery Controller, Message Archiver, WAF Control Center, Web Application Firewall et Web Security Gateway | Injection de commandes système | Exécution de commandes avec privilèges root et compromission complète de l'appliance. | Active | Appliquer les correctifs Barracuda Networks, restreindre les accès administratifs et surveiller les journaux d'administration. | [https://infonewscyber.fr/info/cve-2026-111560-activement-exploitee-injection-de-commandes-dans-le-sy-255a7e2e04eaee5b](https://infonewscyber.fr/info/cve-2026-111560-activement-exploitee-injection-de-commandes-dans-le-sy-255a7e2e04eaee5b)<br>[https://infosec.exchange/@infonewscyber/117594417925492271](https://infosec.exchange/@infonewscyber/117594417925492271) |
| **** | N/A | N/A | FALSE | Adobe Connect 12.12 et antérieures, AEM Cloud Service 2026.10.29023 et antérieur, AEM 6.5 SP25 et antérieur, AEM 6.5 LTS SP3 et antérieur, After Effects 26.5/25.6.6 et antérieurs, Photoshop 2026 27.11 et 2025 26.11.8 et antérieurs, Content Credentials Rust SDK c2pa-v0.91.10 et antérieur, C2PA Tool c2patool-v0.28.5 et antérieur, Audition, Premiere, Media Encoder, Dimension 4.1.9 (macOS) | Multiples vulnérabilités : SSRF, path traversal, autorisation incorrecte, injection CRLF, XXE, injection de code, injection SQL, XSS, dépassements de tampon, use-after-free, déréférencement de pointeur nul | Exécution de code arbitraire sur les postes de travail et les serveurs AEM, avec possibilité d'installation de programmes, de consultation ou de modification de données et de création de comptes à privilèges selon les droits du processus ciblé. | None | Appliquer les correctifs Adobe de novembre 2026 pour chaque produit listé, restreindre l'exposition d'AEM, éviter l'ouverture de fichiers média non fiables et surveiller les journaux des applications exposées. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-adobe-products-could-allow-for-arbitrary-code-execution_2026-130](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-adobe-products-could-allow-for-arbitrary-code-execution_2026-130) |
| **** | N/A | N/A | FALSE | Roundcube Webmail 1.6.x antérieures à 1.6.21 et 1.7.x antérieures à 1.7.6 | Multiples vulnérabilités : exécution de code arbitraire, SSRF, CSRF, contournement de politique de sécurité, déni de service à distance | Compromission du serveur de messagerie web, accès aux boîtes mail des utilisateurs, pivot vers le réseau interne via SSRF et indisponibilité du service. | None | Appliquer les versions Roundcube 1.6.21 ou 1.7.6, restreindre les accès sortants du serveur webmail et surveiller les journaux applicatifs. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1489/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1489/) |
| **** | N/A | N/A | FALSE | Greffon OpenID Connect OpenID Provider (OIDC OP) pour Shibboleth, versions antérieures à 4.3.3 | Contournement de la politique de sécurité | Contournement des contrôles d'authentification et d'autorisation du fournisseur d'identité, avec risque d'accès non autorisé aux applications fédérées. | None | Mettre à jour le greffon OIDC OP vers la version 4.3.3 ou supérieure et auditer les politiques d'authentification. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1491/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1491/) |
| **** | N/A | N/A | FALSE | Produits SAP multiples : NetWeaver AS ABAP/Java, Web Dispatcher, Internet Communication Manager, Internet Graphics Service, Gateway, Message Server, Host Agent, Business Objects BI Platform (Web Intelligence), ABAP Developer Tools | Multiples vulnérabilités : RCE, SSRF, XSS, CSRF, déni de service, contournement de politique de sécurité, atteinte à la confidentialité | Selon les composants, un attaquant pourrait exécuter du code arbitraire, usurper des requêtes, contourner des contrôles d'autorisation, provoquer l'indisponibilité de services métier ou accéder à des données sensibles de l'ERP. | None | Appliquer les notes de sécurité SAP du patch day de novembre 2026 sur l'ensemble des composants concernés, en priorisant les systèmes exposés sur Internet. Restreindre l'accès aux interfaces administratives et techniques, activer la journalisation détaillée et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1497/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1497/) |
| **** | 8.8 | N/A | FALSE | Wireshark (export d'objets SMB depuis le trafic capturé) — branches 4.4 et 4.6 | Débordement d'entier (integer overflow) lors de l'écriture en mémoire, dû à une validation insuffisante des données | Exécution de code arbitraire avec les droits de l'utilisateur qui exécute Wireshark, sur un poste d'analyse souvent riche en accès (collecte, EDR, partages forensic). Risque de vol de données d'enquête et de pivot vers les systèmes de sécurité. | Theoretical | Mettre à jour Wireshark vers les versions intégrant les commits bf270c79 (4.6) et bf4578f1 (4.4). À défaut, éviter l'export d'objets SMB sur des captures non fiables et ouvrir les PCAP dans une VM isolée. | [http://www.zerodayinitiative.com/advisories/ZDI-26-900/](http://www.zerodayinitiative.com/advisories/ZDI-26-900/)<br>`hxxp://www[.]zerodayinitiative[.]com/advisories/ZDI-26-900/` |
| **** | 7.5 | N/A | FALSE | Wireshark — implémentation du réassemblage des fragments LBMC (instances où l'option est activée) | Débordement d'entier (integer overflow) avant écriture en mémoire, dû à une validation insuffisante des données | Exécution de code arbitraire avec les droits de l'utilisateur exécutant Wireshark, sur un poste d'analyse pouvant détenir des accès sensibles. | Theoretical | Mettre à jour vers les versions contenant les commits 4d1c6d96 (4.6) et e2f9595e (4.4). Désactiver le réassemblage LBMC si non nécessaire et analyser les captures non fiables en sandbox. | [http://www.zerodayinitiative.com/advisories/ZDI-26-899/](http://www.zerodayinitiative.com/advisories/ZDI-26-899/)<br>`hxxp://www[.]zerodayinitiative[.]com/advisories/ZDI-26-899/` |
| **** | 7.1 | N/A | FALSE | Wireshark — implémentation du déchiffrement des charges LoRaWAN (instances où l'option est activée) | Erreur de troncature numérique (numeric truncation) conduisant à un calcul incorrect avant écriture en mémoire | Exécution de code arbitraire avec les droits de l'utilisateur exécutant Wireshark, sur des postes d'analyse IoT/OT souvent connectés à des réseaux sensibles. | Theoretical | Mettre à jour vers les versions contenant les commits 8f7bb290 (4.6) et 6527cb12 (4.4). Désactiver le déchiffrement LoRaWAN si non nécessaire et analyser les captures en environnement isolé. | [http://www.zerodayinitiative.com/advisories/ZDI-26-898/](http://www.zerodayinitiative.com/advisories/ZDI-26-898/)<br>`hxxp://www[.]zerodayinitiative[.]com/advisories/ZDI-26-898/` |
| **** | N/A | N/A | FALSE | SAP NetWeaver, Web Dispatcher, Gateway, ABAP Developer Tools, S4CRM, Cloud SDK et autres composants SAP | Multiples vulnérabilités, dont exécution de code arbitraire | Confidentialité, intégrité et disponibilité élevées pour les systèmes SAP exposés ou mal cloisonnés. | None | Appliquer les correctifs SAP correspondants, restreindre l'exposition des interfaces d'administration, surveiller les logs et segmenter les systèmes SAP. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sap-products-could-allow-for-arbitrary-code-execution_2026-128](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-sap-products-could-allow-for-arbitrary-code-execution_2026-128) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="formbook-cible-les-entreprises-europeennes-de-lindustrie-manufacturiere-et-de-la-technologie-avec-des-leurres-de-commande-localises"></div>

## Formbook cible les entreprises européennes de l'industrie manufacturière et de la technologie avec des leurres de commande localisés

### Résumé

L'article d'ANY.RUN est une analyse de malware consacrée à une campagne du family Formbook (infostealer) visant des entreprises européennes des secteurs de la fabrication et de la technologie. La campagne s'appuie sur des leurres de commande (« order lures ») localisés, c'est-à-dire adaptés à la langue et au contexte des victimes ciblées.

---

### Analyse opérationnelle

Formbook est un infostealer largement commoditisé : vol d'identifiants et de cookies de navigateurs, capture de formulaires et keylogging, avec exfiltration vers une infrastructure C2 contrôlée par l'attaquant. Le vecteur repose sur des messages leurres contextualisés (commandes, devis, factures) qui augmentent fortement le taux de clic dans les services achats et ADV. Pour le SOC, la détection doit se concentrer sur la chaîne « messagerie → ouverture de PJ/lien → exécution depuis un répertoire utilisateur → accès aux bases de credentials navigateur → POST HTTP sortant ». Les identifiants volés sont immédiatement réutilisables pour du BEC, de la fraude au virement ou un premier accès à d'autres services (VPN, webmail, SaaS). La localisation des leurres indique une reconnaissance préalable des cibles et une capacité linguistique, ce qui réduit l'efficacité des filtres purement génériques.

---

### Implications stratégiques

Le ciblage de la fabrication et de la technologie européennes s'inscrit dans une logique de monétisation rapide : ces secteurs concentrent des chaînes d'approvisionnement étendues, des échanges de commandes par e-mail et des ERP accessibles à distance. Une compromission de compte achats peut se transformer en fraude fournisseur ou en point d'entrée vers des partenaires. La tendance de fond est la professionnalisation des leurres localisés, qui rend la barrière de la langue inopérante et impose de traiter la messagerie métier comme une surface d'attaque critique, au même titre que le poste de travail.

---

### Recommandations

* Renforcer le filtrage et la sandbox des pièces jointes et liens entrants sur les boîtes achats/ADV.
* Déployer une détection comportementale sur l'accès aux bases de mots de passe navigateurs et l'injection dans les navigateurs.
* Imposer la MFA résistante au phishing sur la messagerie, le VPN et les accès SaaS critiques.
* Mettre en place une validation hors bande systématique des changements de coordonnées bancaires fournisseurs.
* Sensibiliser les équipes métiers aux leurres de commande localisés avec des exemples dans la langue locale.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les métiers exposés (achats, ADV, commerce) et les boîtes mail recevant des commandes externes.
* Durcir les filtres anti-hameçonnage : blocage des pièces jointes exécutables/archives protégées, sandboxing des liens et PJ.
* Former les équipes achats/ADV à reconnaître les leurres de commande localisés (langue, format de facture, urgence).
* Vérifier la couverture EDR sur les postes et la journalisation DNS/proxy pour détecter les exfiltrations HTTP.

#### Phase 2 — Détection et analyse

* Surveiller les créations de processus anormales depuis les dossiers utilisateur (AppData, Temp, Downloads) après ouverture d'une PJ.
* Détecter les accès massifs aux bases de mots de passe navigateurs (Login Data, cookies) et les injections dans les navigateurs.
* Alerter sur les résolutions DNS/proxy vers des domaines récents ou faiblement réputés depuis des postes de bureautique.
* Corréler les signalements utilisateurs de « facture/commande » inattendue avec les journaux de messagerie.

#### Phase 3 — Confinement, éradication et récupération

* Isoler réseau le poste compromis et révoquer les sessions et mots de passe saisis depuis ce poste.
* Bloquer au niveau proxy/DNS les domaines et URL de C2 identifiés lors de l'analyse.
* Rechercher et purger les messages de la campagne dans toutes les boîtes (purge messagerie) et bloquer l'expéditeur.
* Réinitialiser les identifiants des comptes métiers exposés et activer la MFA partout où c'est possible.

#### Phase 4 — Activités post-incident

* Reconstruire le poste ou valider une remédiation complète avant remise en production.
* Mettre à jour les règles de détection avec les artefacts de la campagne (hash, domaines, motifs de leurre).
* Revoir les procédures de validation des commandes/factures fournisseurs (double contrôle hors bande).
* Documenter le retour d'expérience et ajuster la sensibilisation sur les leurres localisés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement les motifs de leurre (objets « order », « purchase order », langues locales) dans la messagerie sur 90 jours.
* Chasser les connexions sortantes HTTP POST atypiques depuis des postes bureautiques vers des domaines inconnus.
* Rechercher les exécutions de binaires non signés depuis des chemins utilisateur et les chaînes parentes suspectes (Office, archiveurs).
* Vérifier l'absence de persistance (Run keys, tâches planifiées) sur les postes ayant ouvert des PJ de la campagne.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Hameçonnage par pièce jointe (leurre de commande/facture localisé) |
| **T1204.002** | Exécution par l'utilisateur d'un fichier malveillant |
| **T1555.003** | Vol d'identifiants stockés dans les navigateurs |
| **T1056.001** | Keylogging via l'infostealer Formbook |
| **T1071.001** | Communication C2 via HTTP/HTTPS |

---

### Sources

* [https://any.run/cybersecurity-blog/formbook-malware-analysis-november-2026/](https://any.run/cybersecurity-blog/formbook-malware-analysis-november-2026/)


---

<div id="astuce-de-developpement-de-malware-70-injection-de-processus-par-point-darret-materiel-exemple-simple-en-c"></div>

## Astuce de développement de malware 70 : injection de processus par point d'arrêt matériel. Exemple simple en C

### Résumé

Billet technique de la série « Malware development trick » qui présente, avec un exemple simple en langage C, une technique d'injection de code dans un processus distant reposant sur l'usage de points d'arrêt matériels (registres de débogage) plutôt que sur les mécanismes d'injection classiques.

---

### Analyse opérationnelle

Cette technique illustre une variante d'injection de processus (T1055) qui détourne l'exécution d'un thread légitime via les registres de débogage matériels, ce qui peut passer sous les radars de certaines solutions ne surveillant que les API d'injection classiques (CreateRemoteThread, APC, hollowing). Pour le SOC, l'enjeu est la visibilité sur les appels de manipulation de contexte de thread et sur les écritures mémoire inter-processus. Les EDR modernes couvrent partiellement ces événements, mais la détection repose surtout sur la corrélation comportementale : binaire non signé, handle vers un processus sensible, écriture mémoire puis reprise d'exécution. La publication de ce type de code en accès libre abaisse la barrière d'entrée pour des acteurs peu sophistiqués et alimente les kits de malware commoditisés.

---

### Implications stratégiques

La diffusion publique de techniques d'injection avancées accélère leur adoption par des groupes criminels et ransomware, et raccourcit la fenêtre pendant laquelle les détections génériques restent efficaces. Les organisations doivent considérer la protection contre l'injection comme une exigence de conception (durcissement des processus critiques, segmentation des privilèges) et non comme un simple réglage d'antivirus. La tendance est à la combinaison de techniques furtives et de malwares commoditisés, ce qui élargit le spectre des attaquants capables de contourner les défenses de base.

---

### Recommandations

* Activer les protections anti-injection (ACG, CIG, EAF) sur les processus critiques et les navigateurs.
* Vérifier la couverture EDR des événements SetThreadContext/GetThreadContext et des écritures mémoire distantes.
* Appliquer une politique d'application control limitant l'exécution de binaires non signés depuis les répertoires utilisateur.
* Tester régulièrement les détections avec des échantillons de techniques d'injection publiques (exercices purple team).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier que l'EDR capture les événements de manipulation de threads et de contexte (SetThreadContext, debug registers).
* Activer les protections anti-injection (ACG, CIG, EAF) sur les processus sensibles (navigateurs, LSASS, messagerie).
* Documenter les processus légitimes utilisés comme cibles d'injection pour réduire les faux positifs.

#### Phase 2 — Détection et analyse

* Détecter les appels à SetThreadContext/GetThreadContext sur des threads d'un processus distant.
* Surveiller les écritures mémoire inter-processus (WriteProcessMemory, NtMapViewOfSection) suivies d'un réveil de thread.
* Alerter sur les binaires non signés exécutés depuis des chemins temporaires et ouvrant un handle sur un processus tiers.
* Corréler les événements d'injection avec des connexions réseau sortantes inhabituelles du processus cible.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre puis isoler la machine présentant une injection inter-processus confirmée.
* Tuer le processus cible compromis et le processus injecteur, puis collecter la mémoire avant remédiation.
* Bloquer les artefacts (hash, chemins, domaines) sur l'ensemble du parc via l'EDR et le proxy.

#### Phase 4 — Activités post-incident

* Analyser l'échantillon pour extraire les techniques exactes et mettre à jour les règles de détection.
* Réévaluer la posture des protections anti-injection et des politiques d'application control.
* Reconstruire le système si la persistance ou l'élévation de privilèges ne peut être exclue.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les chaînes d'événements « allocation mémoire distante → écriture → modification de contexte de thread » sur 30 jours.
* Chasser les exécutables non signés avec un nombre anormal de handles vers des processus d'autres éditeurs.
* Examiner les journaux de chargement de pilotes/debug pour détecter un usage abusif des registres de débogage.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1055** | Injection de processus via détournement de threads par points d'arrêt matériels |
| **T1106** | Utilisation d'API natives Windows (debug registers, gestion de threads) pour l'injection |
| **T1027** | Obfuscation de l'exécution pour contourner les contrôles de sécurité |

---

### Sources

* [https://cocomelonc.github.io/malware/2026/11/10/malware-tricks-70.html](https://cocomelonc.github.io/malware/2026/11/10/malware-tricks-70.html)


---

<div id="detecter-les-agents-dormants-caches-dans-les-neurones-des-modeles-dia"></div>

## Détecter les agents dormants cachés dans les neurones des modèles d'IA

### Résumé

Publication de Microsoft Threat Intelligence consacrée à la détection d'« agents dormants » (sleeper agents) dissimulés dans les neurones de modèles d'IA : des modèles dont le comportement malveillant reste latent et n'est déclenché que par des entrées ou conditions spécifiques.

---

### Analyse opérationnelle

Le sujet déplace la problématique de sécurité vers la couche modèle : un modèle piégé peut se comporter normalement lors des tests et lors de l'usage courant, puis adopter un comportement malveillant sur un déclencheur précis. Pour les équipes de défense, cela implique de traiter les modèles comme des artefacts logiciels à part entière : provenance, intégrité, signature, tests comportementaux avant déploiement, et surveillance continue des écarts de comportement en production. Les pipelines MLOps (dépôts de modèles, registres, adaptateurs) deviennent des cibles de chaîne d'approvisionnement au même titre qu'un package logiciel.

---

### Implications stratégiques

L'adoption rapide d'agents IA dans les processus métiers crée une nouvelle surface d'attaque difficile à auditer avec les outils classiques : un modèle compromis peut influencer des décisions, exfiltrer des données via ses sorties ou servir de relais dans une chaîne d'agents. Les organisations doivent intégrer la sécurité des modèles dans leur gouvernance IA et leur gestion des tiers, sous peine de voir la confiance accordée aux systèmes d'IA devenir un vecteur de risque opérationnel et réputationnel.

---

### Recommandations

* Inventorier et signer les modèles déployés, avec contrôle d'intégrité à chaque mise en production.
* Mettre en place des tests comportementaux et des jeux de prompts adverses avant tout déploiement de modèle.
* Journaliser les entrées/sorties des modèles exposés et surveiller les dérives comportementales.
* Restreindre les droits de publication sur les registres de modèles et auditer les pipelines MLOps.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les modèles d'IA utilisés (internes, open source, tiers) et leurs sources d'approvisionnement.
* Définir une politique de validation des modèles : provenance, hash, tests comportementaux avant mise en production.
* Mettre en place une journalisation des entrées/sorties des modèles exposés aux utilisateurs et aux agents automatisés.

#### Phase 2 — Détection et analyse

* Surveiller les changements de comportement d'un modèle sur des entrées déclenchantes (tests de robustesse, jeux de prompts adverses).
* Détecter les modifications non autorisées de poids, de configuration ou de version de modèle en production.
* Alerter sur les modèles dont les sorties divergent fortement entre environnements de test et de production.

#### Phase 3 — Confinement, éradication et récupération

* Retirer le modèle suspect du service et revenir à une version validée et signée.
* Suspendre les agents ou automatisations s'appuyant sur le modèle compromis.
* Bloquer la source d'approvisionnement du modèle et notifier les équipes consommatrices.

#### Phase 4 — Activités post-incident

* Analyser l'origine de la compromission (dépôt, registre de modèles, fournisseur) et corriger la chaîne d'approvisionnement.
* Renforcer les contrôles d'intégrité et de signature des artefacts de modèles.
* Documenter les indicateurs comportementaux observés pour enrichir les tests de non-régression.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des modèles ou adaptateurs (LoRA, checkpoints) d'origine non vérifiée dans les registres internes.
* Examiner les journaux d'inférence pour des motifs de déclenchement répétés ou des sorties anormales corrélées à certaines entrées.
* Auditer les accès aux pipelines d'entraînement et de publication de modèles pour détecter une altération.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromission de la chaîne d'approvisionnement logicielle via un modèle d'IA piégé |
| **T1027** | Comportement dissimulé (backdoor dormant) activé par un déclencheur |

---

### Sources

* [https://www.microsoft.com/en-us/security/blog/2026/11/10/detecting-sleeper-agents-hiding-in-ai-model-neurons/](https://www.microsoft.com/en-us/security/blog/2026/11/10/detecting-sleeper-agents-hiding-in-ai-model-neurons/)


---

<div id="le-reseau-de-fraude-doppelcart-depasse-les-250-000-domaines"></div>

## Le réseau de fraude DoppelCart dépasse les 250 000 domaines

### Résumé

Recorded Future (Insikt Group) documente DoppelCart, un réseau de fraude à l'achat en ligne d'environ 261 700 domaines suspects identifiés entre mars et octobre 2026. Ces fausses boutiques copient le branding et les fiches produits de détaillants légitimes pour obtenir des informations personnelles et de paiement, certaines capturant aussi les codes de vérification émis par les banques. Le réseau, révélé en septembre 2026 par la société allemande Nebty (plus de 119 000 sites), utilisait majoritairement le TLD .shop avant une diversification vers .com à partir de septembre 2026. Environ 40 % des sites observés avant le 17 octobre 2026 restaient actifs. Les marques usurpées proviennent principalement des États-Unis, du Royaume-Uni, d'Australie, du Canada et d'Allemagne.

---

### Analyse opérationnelle

La fraude se situe côté consommateur et côté marque : les pages de paiement transmettent en temps réel les données de carte et parfois les codes OTP aux serveurs des attaquants, ce qui permet d'autoriser des transactions pendant que la victime croit finaliser un achat légitime. Pour les équipes de sécurité, l'enjeu est double : protection de la marque (détection d'usurpation, takedown) et détection réseau interne (employés visitant ces sites depuis le réseau d'entreprise, risque de compromission de données de paiement professionnelles). L'usage de templates partagés, de configurations de paiement communes et d'une plateforme e-commerce de type Medusa facilite la chasse par similarité technique plutôt que par listes de domaines, dont le volume rend le blocage exhaustif impraticable.

---

### Implications stratégiques

L'industrialisation de la fraude à grande échelle (centaines de milliers de domaines, automatisation de la copie de catalogues) érode la confiance des consommateurs dans le commerce en ligne et expose les détaillants à un risque réputationnel et juridique. La captation des codes OTP remet en cause les mécanismes de vérification forts utilisés par les banques et déplace la responsabilité vers la détection comportementale des transactions. Pour les organisations, la lutte contre l'usurpation de marque devient un processus continu nécessitant surveillance, partenariats de takedown et coordination avec le secteur financier.

---

### Recommandations

* Mettre en place une surveillance continue de l'usurpation de marque (domaines, visuels, catalogues) avec alertes automatisées.
* Bloquer au niveau proxy/DNS les TLD et clusters identifiés comme frauduleux, en complément des listes de domaines.
* Sensibiliser les collaborateurs aux fausses boutiques et interdire l'usage de cartes d'entreprise sur des sites non validés.
* Coordonner avec les prestataires de paiement et les banques pour détecter les schémas de captation d'OTP.
* Industrialiser les procédures de takedown et mesurer le taux de réactivation des sites frauduleux.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une surveillance de l'usurpation de marque (domaines, visuels, catalogues copiés) et un canal de signalement consommateur.
* Identifier les contacts de takedown (registrars, hébergeurs, plateformes de paiement, CERT) et préparer des modèles de notification.
* Cartographier les actifs de marque à protéger (logos, fiches produits, noms de domaine proches).

#### Phase 2 — Détection et analyse

* Détecter les nouveaux domaines copiant le branding et les fiches produits, en particulier sur les TLD .shop et .com.
* Surveiller les signalements clients de commandes non reçues ou de pages de paiement suspectes.
* Analyser les modèles de paiement partagés et les configurations de plateforme e-commerce (ex. Medusa) réutilisées entre sites frauduleux.

#### Phase 3 — Confinement, éradication et récupération

* Faire bloquer les domaines frauduleux (takedown, safe browsing, filtres internes) et demander la suspension des comptes marchands/paiement.
* Publier une alerte consommateur et un canal de vérification des boutiques officielles.
* Notifier les prestataires de paiement et les banques émettrices des schémas de fraude observés.

#### Phase 4 — Activités post-incident

* Suivre le taux de réactivation des domaines bloqués et relancer les takedowns si nécessaire.
* Mettre à jour les règles de détection de marque avec les nouveaux TLD et modèles de templates.
* Évaluer l'impact réputationnel et ajuster la communication client.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux web/DNS internes des résolutions vers des domaines de boutiques récemment enregistrés.
* Chasser les indicateurs de collecte de codes de vérification bancaire (formulaires demandant un OTP) sur les sites suspects.
* Corréler les infrastructures d'hébergement et les configurations de paiement partagées pour identifier de nouveaux clusters.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1583.001** | Acquisition d'infrastructure de domaines pour la fraude à grande échelle |
| **T1656** | Usurpation de marques de détaillants légitimes (fausses boutiques) |
| **T1598** | Collecte d'informations personnelles et de paiement via des formulaires frauduleux |
| **T1566** | Sollicitation des victimes vers des sites frauduleux (publicité, liens, promotions) |

---

### Sources

* [https://www.recordedfuture.com/blog/doppelcart-fraud-network-grows-domains](https://www.recordedfuture.com/blog/doppelcart-fraud-network-grows-domains)


---

<div id="ghostframe-un-nouvel-implant-esxi-lie-au-ransomware-settra"></div>

## GhostFrame : un nouvel implant ESXi lié au ransomware Settra

### Résumé

Recorded Future (Insikt Group) documente GhostFrame, un framework de post-exploitation et de commande-contrôle jusqu'ici non documenté, conçu pour les hyperviseurs VMware ESXi compromis. Une fois l'accès root obtenu, GhostFrame offre une interface web unique (sections « Sessions » et « Builder ») permettant de gérer les machines virtuelles, exécuter des commandes, récolter des identifiants Windows et pivoter dans le réseau. Le builder génère un implant ELF nommé vmhostd-core qui se copie dans /opt/vmhostd-core, modifie /etc/rc.local.d/local.sh pour persister, désactive toutes les cinq secondes le pare-feu ESXi et le contrôle execInstalledOnly, exécute /sbin/auto-backup.sh et masque son processus sous le nom vmhostd. L'implant est associé au groupe d'activité TAG-218, dont les opérations recoupent celles du ransomware Settra. L'implant n'exploite pas de vulnérabilité : il requiert un accès root préalable.

---

### Analyse opérationnelle

La compromission d'un hyperviseur donne un point d'accès centralisé à toutes les VM hébergées : l'attaquant n'a plus besoin de compromettre chaque système individuellement. Les points de détection concrets sont la modification du script de démarrage local.sh, l'apparition d'un binaire dans /opt, la désactivation répétée du pare-feu et d'execInstalledOnly, et un processus usurpant le nom d'un démon VMware légitime. La persistance survit aux reboots via auto-backup.sh, ce qui signifie qu'un simple redémarrage ne nettoie pas l'hôte. La collecte d'identifiants Windows depuis l'hyperviseur prépare une propagation latérale et un déploiement ransomware, avec un risque de destruction des sauvegardes et des snapshots.

---

### Implications stratégiques

L'hyperviseur devient une cible de premier choix pour les groupes ransomware : il concentre la valeur (données, services critiques) et permet un impact maximal en un seul point. La chaîne d'attaque TAG-218 / Settra illustre la convergence entre frameworks de post-exploitation dédiés à la virtualisation et opérations de chiffrement. Les organisations doivent considérer l'infrastructure de virtualisation comme un actif de niveau critique, avec segmentation du réseau de management, durcissement ESXi et surveillance dédiée, faute de quoi la résilience de tout le SI repose sur un seul hôte compromis.

---

### Recommandations

* Durcir les hôtes ESXi : execInstalledOnly activé, pare-feu verrouillé, accès root restreint et journalisé.
* Surveiller l'intégrité de /etc/rc.local.d/local.sh et l'apparition de binaires dans /opt et sur les datastores.
* Segmenter le réseau de management de l'hyperviseur et interdire les connexions sortantes non nécessaires.
* Prévoir une rotation massive des identifiants Windows en cas de compromission d'un hôte ESXi.
* Tester la restauration hors ligne des VM et vérifier l'isolation des sauvegardes face à un ransomware.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Restreindre l'accès root aux hôtes ESXi (comptes nominatifs, MFA sur vCenter, bastion dédié).
* Activer et verrouiller execInstalledOnly, le pare-feu ESXi et l'audit des commandes shell.
* Sauvegarder et surveiller l'intégrité des scripts de démarrage (/etc/rc.local.d/local.sh) et des datastores.
* Segmenter le réseau de management de l'hyperviseur du réseau de production.

#### Phase 2 — Détection et analyse

* Surveiller les modifications de /etc/rc.local.d/local.sh et l'apparition de binaires dans /opt (ex. /opt/vmhostd-core).
* Alerter sur la désactivation du pare-feu ESXi ou du contrôle execInstalledOnly, en particulier si répétée toutes les quelques secondes.
* Détecter les processus dont le nom imite des démons légitimes (vmhostd vs vmware-hostd) et les connexions C2 sortantes depuis l'hyperviseur.
* Surveiller les accès anormaux aux datastores et l'exécution de binaires depuis ceux-ci.

#### Phase 3 — Confinement, éradication et récupération

* Isoler l'hôte ESXi compromis du réseau de management et des datastores partagés.
* Révoquer les comptes root/administrateurs ESXi et les clés SSH, réinitialiser les secrets exposés.
* Suspendre les VM critiques si nécessaire et vérifier l'intégrité des sauvegardes avant toute restauration.
* Rechercher et bloquer les indicateurs C2 et les artefacts de l'implant sur les autres hôtes.

#### Phase 4 — Activités post-incident

* Réinstaller l'hyperviseur à partir d'une image propre et restaurer les configurations validées.
* Auditer les identifiants Windows potentiellement collectés et procéder à une rotation massive.
* Renforcer les contrôles d'intégrité des scripts de démarrage et la surveillance des hyperviseurs.
* Revoir les procédures de réponse ransomware en environnement virtualisé.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur tous les hôtes ESXi les fichiers /opt/vmhostd-core et les modifications de local.sh sur 90 jours.
* Chasser les connexions sortantes depuis les hyperviseurs vers des destinations non référencées.
* Rechercher les traces de désactivation répétée du pare-feu et d'execInstalledOnly dans les journaux ESXi.
* Vérifier les accès root récents et les connexions SSH depuis des postes d'administration non autorisés.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1037.004** | Persistance via script de démarrage rc.local sur ESXi |
| **T1562.004** | Désactivation du pare-feu ESXi par l'implant |
| **T1562.001** | Désactivation du contrôle execInstalledOnly (exécution de binaires non signés) |
| **T1003** | Collecte d'identifiants depuis les systèmes Windows hébergés |
| **T1021** | Pivot vers les machines virtuelles et l'infrastructure interne |
| **T1036** | Masquage du processus sous le nom légitime vmhostd |

---

### Sources

* [https://www.recordedfuture.com/blog/ghostframe-esxi-implant-settra-ransomware](https://www.recordedfuture.com/blog/ghostframe-esxi-implant-settra-ransomware)


---

<div id="cet-exploit-viral-de-triangulation-doppler-daeronef-jen-ai-construit-une-replication-fonctionnelle"></div>

## Cet exploit viral de triangulation Doppler d'aéronef ? J'en ai construit une réplication fonctionnelle.

### Résumé

Un chercheur publie en « controlled release » un outil nommé doppler ninja permettant de localiser géographiquement une personne à partir des tonalités Doppler d'aéronefs captées par le microphone dans un enregistrement audio. La méthode extrait les tonalités descendantes, les apparie aux enregistrements publics ADS-B, puis note chaque cellule d'une grille autour d'une ville. Sur 135,2 heures de ses propres enregistrements (quatre sessions, 10 jours UTC), l'outil a trouvé la bonne cellule à 227 m de l'adresse réelle avec 6 tonalités cohérentes en horloge, tandis qu'aucun des 500 jeux de tonalités décalés dans le temps (contrôles) n'a atteint ce score. Un portage des mêmes règles sur l'ensemble de la métropole Dallas–Fort Worth (28 875 cellules, sans indice de ville) a placé la meilleure cellule à environ 0,4 km de l'adresse, avec 0 contrôle sur 200 atteignant le score de 6. Trois exécutions indépendantes ont donné des résultats à moins d'un kilomètre du domicile. L'auteur précise que l'instance hébergée est protégée par mot de passe et que le code peut être exécuté localement.

---

### Analyse opérationnelle

L'attaque ne nécessite aucun accès au système de la victime : un simple enregistrement audio contenant du bruit ambiant suffit, ce qui abaisse fortement la barrière pour du doxxing, du harcèlement ou de la reconnaissance physique ciblée. Pour un SOC, la détection est difficile car il n'y a pas d'artefact hôte : les signaux exploitables sont surtout les requêtes massives vers les API ADS-B publiques, l'installation locale d'outils de traitement audio et la publication de contenus audio non filtrés. Les mesures techniques relèvent de l'hygiène : coupure matérielle du microphone hors usage, réduction de bruit, filtrage passe-bande des diffusions, suppression des passages ambiants dans les enregistrements publiés, blocage proxy des API de tracking aérien non nécessaires. La surface d'attaque s'étend à tous les canaux audio : réunions enregistrées, podcasts, streams, notes vocales, vidéos de démonstration.

---

### Implications stratégiques

Cette publication illustre la convergence entre OSINT, traitement du signal et données publiques aériennes, et invalide l'hypothèse selon laquelle un flux audio ne révèle qu'un environnement sonore générique. Les populations à risque sont les dirigeants, journalistes, lanceurs d'alerte, créateurs de contenu et salariés en télétravail dont les réunions sont diffusées ou stockées. Le risque organisationnel est double : atteinte à la sécurité physique des personnes et fuite d'informations sur des sites sensibles (usines, laboratoires, datacenters) reconnaissables au bruit de fond. La disponibilité d'un outil clé en main, même en diffusion restreinte, accroît la probabilité de réutilisation opportuniste et pose la question de la responsabilité des plateformes de diffusion et des politiques internes de captation audio.

---

### Recommandations

* Imposer la coupure matérielle du microphone pour toute diffusion publique et pour les postes en zone sensible.
* Filtrer les enregistrements audio publiés (passe-bande, suppression des passages ambiants) avant diffusion.
* Bloquer au proxy les API ADS-B publiques non justifiées par un besoin métier.
* Intégrer le risque de géolocalisation audio dans les revues d'exposition OSINT des personnalités à risque.
* Sensibiliser les équipes production/communication et les créateurs de contenu internes.
* Surveiller les dépôts et instances de l'outil pour détecter une réutilisation ciblée contre l'organisation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les personnes à forte exposition (streamers, dirigeants, journalistes, télétravailleurs) au risque de géolocalisation par audio ambiant capté au microphone.
* Cartographier les flux audio sortants (réunions enregistrées, podcasts, streams, notes vocales) et les stockages associés.
* Restreindre les requêtes sortantes vers les API ADS-B publiques (OpenSky, ADS-B Exchange) depuis les postes de travail et limiter l'accès aux proxys non filtrés.
* Définir une politique de mute matériel du microphone et de réduction de bruit pour les diffusions publiques.

#### Phase 2 — Détection et analyse

* Surveiller les requêtes massives ou scriptées vers des API de données de vol (volumétrie, user-agent, cadence) depuis le SI.
* Détecter l'installation ou l'exécution locale d'outils de géolocalisation audio (dépôts GitHub, conteneurs, scripts Python de traitement de tonalités).
* Analyser les enregistrements publiés en ligne pour vérifier la présence de bruits d'aéronefs exploitables (revue ponctuelle).
* Corréler les tentatives de doxxing signalées avec des pics de scraping ADS-B.

#### Phase 3 — Confinement, éradication et récupération

* Retirer ou re-traiter les contenus audio publiés contenant des séquences exploitables (filtrage passe-bande, suppression des passages ambiants).
* Bloquer au niveau proxy les domaines et API de tracking aérien non nécessaires à l'activité.
* Suspendre les comptes ou instances ayant servi à l'hébergement de l'outil si l'usage est interne et non autorisé.
* Accompagner la personne ciblée : revue de l'exposition OSINT, durcissement des paramètres de confidentialité, protection physique si nécessaire.

#### Phase 4 — Activités post-incident

* Documenter la méthode, les enregistrements concernés et les mesures de réduction appliquées.
* Mettre à jour la charte de diffusion (audio, métadonnées, horaires) et les clauses de confidentialité des prestataires de streaming.
* Évaluer les obligations de notification si des données personnelles ont été exposées (RGPD).
* Former les équipes communication/production aux risques de fuite par canal auxiliaire.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy les accès aux domaines de tracking aérien et aux dépôts de l'outil.
* Rechercher des artefacts de traitement audio (ffmpeg, bibliothèques de détection de tonalité) sur les postes sensibles.
* Surveiller les places de marché et forums OSINT pour la réutilisation de la méthode contre des cibles de l'organisation.
* Tester périodiquement la résistance de ses propres diffusions à une tentative de géolocalisation contrôlée.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `doppler[.]ninja` | Medium |
| DOMAIN | `reddit[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1591** | Collecte d'informations sur la victime (localisation physique) via sources ouvertes |
| **T1593** | Recherche sur sites web et services ouverts (données publiques ADS-B) |

---

### Sources

* [https://doinfinitely.github.io/doppler-triangulation-attack/](https://doinfinitely.github.io/doppler-triangulation-attack/)


---

<div id="nukerat-framework-un-framework-post-exploitation-pour-les-operations-avancees-de-red-team"></div>

## NukeRat Framework : un framework post-exploitation pour les opérations avancées de Red Team

### Résumé

Le dépôt GitHub nukeratframework/nukerat publie NukeRat, un framework de post-exploitation sous licence GPLv3 destiné aux opérations Red Team avancées. Le projet revendique plus de 550 utilitaires BOF et .NET, un C2 personnalisé capable de s'appuyer sur des plateformes externes (Telegram, Discord), des techniques d'évasion runtime (syscalls indirects, stack spoofing, sleep mask, patch AMSI/ETW), plusieurs modes d'injection (VirtualAlloc, section, module stomping), une intégration Living off the Land couvrant plus de 240 binaires Windows natifs (LOLBAS), une personnalisation de PE pour l'évasion statique, des implants multiplateformes Windows/Linux/macOS avec support ARM, des implants Linux compatibles BOF, une intégration d'agents IA (DeepSeek, modèles locaux) et la génération de rapports incluant commandes exécutées, IOC et hôtes compromis. Le dépôt compte environ 105 étoiles et 20 forks, avec une version 1.4.8-rc.5.

---

### Analyse opérationnelle

La mise à disposition libre d'un framework combinant évasion runtime avancée, C2 via plateformes grand public et arsenal LOLBAS abaisse fortement le coût d'entrée pour des groupes non étatiques, y compris des affiliés ransomware. Les canaux C2 détournés (Telegram, Discord) compliquent le filtrage car ils se confondent avec un usage légitime. Les équipes SOC doivent prioriser la détection comportementale : appels syscall indirects, altération de la pile, patchs AMSI/ETW en mémoire, allocations mémoire suspectes, chaînes LOLBAS et connexions sortantes vers des API de messagerie depuis des serveurs. Les rapports générés par l'outil constituent aussi une source d'IOC exploitable en rétro-hunting. La personnalisation de PE et l'obfuscation SGN réduisent l'efficacité des signatures statiques, rendant les contrôles applicatifs (WDAC/AppLocker) et la surveillance mémoire indispensables.

---

### Implications stratégiques

La démocratisation d'outils offensifs matures et gratuits modifie l'économie de la menace : des capacités auparavant réservées à des acteurs financés deviennent accessibles à des attaquants isolés, ce qui brouille l'attribution et accroît le volume d'intrusions sophistiquées. L'intégration de LLM dans la chaîne opérationnelle annonce une automatisation accrue de la reconnaissance et de l'exécution. Pour les organisations, la conséquence décisionnelle est un rééquilibrage des investissements vers la détection comportementale, la segmentation et la maîtrise des canaux sortants, au détriment des seules signatures. Le débat sur la responsabilité des plateformes d'hébergement de code offensif et sur la surveillance des projets open source à double usage reste ouvert.

---

### Recommandations

* Renforcer la détection comportementale des techniques d'évasion runtime (syscalls indirects, stack spoofing, patch AMSI/ETW).
* Bloquer ou encadrer strictement les connexions sortantes vers les API Telegram/Discord depuis les serveurs.
* Déployer WDAC/AppLocker et restreindre l'exécution des binaires LOLBAS non nécessaires.
* Ajouter les artefacts du framework aux règles Sigma et aux recherches rétrospectives.
* Surveiller les dépôts clones et forks pour détecter des variantes utilisées en intrusion réelle.
* Tester la couverture EDR face aux modes d'injection proposés lors d'exercices purple team.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les binaires LOLBAS présents dans le parc et les règles de blocage applicables.
* Vérifier la couverture EDR sur les techniques d'injection (module stomping, sections) et sur les patchs AMSI/ETW en mémoire.
* Préparer des règles de détection pour les canaux C2 détournés (Telegram, Discord, webhooks) et les connexions sortantes atypiques.
* Restreindre l'accès aux dépôts de code offensif et aux domaines de distribution d'outils non nécessaires à l'activité.

#### Phase 2 — Détection et analyse

* Détecter les appels indirects aux syscalls et les anomalies de pile (stack spoofing) via capteurs noyau/ETW.
* Surveiller les tentatives de patch AMSI/ETW et les modifications mémoire de processus sécurité.
* Détecter l'exécution de chaînes LOLBAS (certutil, rundll32, regsvr32, mshta) avec arguments inhabituels.
* Analyser le trafic sortant vers api.telegram[.]org, discord[.]com et webhooks associés depuis des serveurs.
* Rechercher les artefacts d'implants multiplateformes (Windows, Linux, macOS ARM) et les clés d'opérateur générées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes présentant des indicateurs d'implant et préserver la mémoire avant extinction.
* Bloquer au niveau pare-feu/proxy les canaux C2 identifiés et les domaines de distribution de l'outil.
* Révoquer les identifiants compromis et les tickets Kerberos suspects, renforcer la surveillance des mouvements latéraux.
* Reconstruire les hôtes confirmés compromis plutôt que de tenter une désinfection en place.

#### Phase 4 — Activités post-incident

* Reconstituer la chronologie d'exécution à partir des journaux EDR et des rapports générés par l'outil (commandes, hôtes, IOC).
* Mettre à jour les règles Sigma et les signatures EDR avec les artefacts observés.
* Revoir les contrôles applicatifs (WDAC/AppLocker) et la politique LOLBAS.
* Conduire un retour d'expérience sur la détection des techniques d'évasion runtime.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les motifs d'injection module stomping et les allocations mémoire RWX/RX anormales.
* Rechercher les connexions persistantes vers des plateformes de messagerie depuis des actifs serveurs.
* Rechercher les clés d'opérateur et fichiers de configuration du framework sur les postes et serveurs.
* Traquer les chaînes d'exécution LOLBAS corrélées à des téléchargements externes.
* Surveiller les forks et dépôts clones du framework pour détecter des variantes modifiées utilisées en intrusion.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://github[.]com/nukeratframework/nukerat` | High |
| DOMAIN | `nukerat[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1055** | Injection de code dans un processus (VirtualAlloc, section, module stomping) |
| **T1562.001** | Altération des défenses : patch AMSI/ETW, sleep mask |
| **T1218** | Exécution via binaires système légitimes (intégration LOLBAS, plus de 240 binaires) |
| **T1071.001** | C2 via protocoles web et plateformes externes (Telegram, Discord) |
| **T1027** | Obfuscation et évasion statique (personnalisation PE, SGN) |

---

### Sources

* [https://github.com/nukeratframework/nukerat](https://github.com/nukeratframework/nukerat)


---

<div id="evolution-des-menaces-informatiques-au-t3-2026-statistiques-mobiles"></div>

## Évolution des menaces informatiques au T3 2026. Statistiques mobiles

### Résumé

Kaspersky publie les statistiques mobiles de son rapport trimestriel Q3 2026, issues de Kaspersky Security Network. Plus de 1,66 million d'attaques impliquant malware, adware ou logiciels indésirables mobiles ont été bloquées, contre 1 996 823 au trimestre précédent. La catégorie Trojan-Banker représente 31,63 % des applications malveillantes détectées, avec 378 456 échantillons Android et 119 688 packages de chevaux de Troie bancaires. Faits marquants : en juillet, une application se faisant passer pour Google Play Protect et ciblant des utilisateurs brésiliens utilisait le modèle DistilBERT pour interpréter des commandes en langage naturel envoyées par le serveur C2, avec des traces suggérant une génération côté serveur par un LLM ; en août, un trojan analysait les images de la galerie et prenait des captures d'écran à la recherche de données bancaires (dont les codes CVV) via un modèle d'IA embarqué et actualisable ; le trojan d'abonnement Trojan.AndroidOS.Subscriber.bh est réapparu sur Google Play déguisé en application de thèmes de clavier, ciblant principalement la Thaïlande, via une WebView masquée et l'interception du code de confirmation. Côté iOS, 13 packages PHP infectés sur Packagist injectaient des liens vers des casinos frauduleux et, sur iOS uniquement, une iframe masquée chargeant le kit d'exploitation DarkSword, délivrant un module espion volant le trousseau, les mots de passe Wi-Fi, les SMS et les photos, ainsi que des modules de vol de portefeuilles crypto et de phrases de récupération ; la même chaîne a été retrouvée dans l'application FomoPeek publiée sur l'App Store, et des versions infectées d'applications iOS populaires ont été distribuées via Telegram moyennant l'achat d'un certificat développeur.

---

### Analyse opérationnelle

Le mobile reste une porte d'entrée majeure et un canal de fraude directe, avec une professionnalisation des leurres (faux outils de sécurité, faux trackers crypto, thèmes de clavier). L'usage de modèles d'IA embarqués et côté serveur permet d'adapter la fraude en langage naturel et d'élargir les capacités après déploiement, ce qui complique la détection par signatures. Les équipes SOC doivent surveiller l'abus des services d'accessibilité, les WebView masquées, l'interception de SMS et les accès massifs à la galerie, ainsi que les flux vers des endpoints d'abonnement frauduleux. La compromission de packages PHP sur Packagist constitue un vecteur de supply chain logicielle touchant les sites web et, par ricochet, les visiteurs iOS : l'audit des dépendances Composer et la détection d'iframes injectées deviennent prioritaires. Les politiques MDM doivent interdire le sideloading et l'installation de certificats développeur non gérés.

---

### Implications stratégiques

La confiance dans les stores officiels s'érode : des applications malveillantes réapparaissent sur Google Play et sur l'App Store, et des applications infectées circulent via Telegram avec des certificats développeur. Le ciblage régional (Brésil, Thaïlande) montre une segmentation fine des campagnes de fraude. L'intégration de l'IA générative dans les opérations malveillantes annonce une hausse du volume et de la qualité des fraudes, avec un risque financier direct pour les clients des banques et des plateformes crypto. Pour les décideurs, cela implique de renforcer la détection côté mobile, la gouvernance des dépendances open source et la sensibilisation des utilisateurs, tout en anticipant une pression réglementaire accrue sur les distributeurs d'applications.

---

### Recommandations

* Interdire le sideloading et l'installation de certificats développeur non gérés via MDM.
* Surveiller l'abus des services d'accessibilité, des WebView masquées et l'interception de SMS.
* Auditer les dépendances Composer/Packagist et détecter les iframes injectées ciblant iOS.
* Sensibiliser aux leurres : faux Play Protect, faux trackers de portefeuille, thèmes de clavier.
* Protéger les portefeuilles crypto et les phrases de récupération par stockage hors ligne.
* Bloquer au niveau DNS/proxy les domaines d'abonnement et de casino frauduleux identifiés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les applications mobiles autorisées et durcir les politiques MDM (interdiction du sideloading, blocage des certificats développeur non gérés).
* Vérifier l'activation de Google Play Protect et des contrôles d'intégrité côté iOS.
* Mettre en place une surveillance des dépendances Composer/Packagist dans les projets web.
* Sensibiliser les utilisateurs aux applications leurres (faux Play Protect, faux trackers de portefeuille crypto, thèmes de clavier).

#### Phase 2 — Détection et analyse

* Détecter l'abus des services d'accessibilité et des WebView masquées utilisés pour l'ouverture de liens d'abonnement.
* Surveiller les applications demandant l'accès à la galerie, aux SMS et aux captures d'écran de façon disproportionnée.
* Analyser les flux réseau mobiles vers des C2 connus et les balises d'abonnement frauduleuses.
* Contrôler l'intégrité des packages PHP déployés et détecter les iframes injectées ciblant iOS.
* Surveiller les installations d'applications hors store et l'usage de certificats développeur personnels.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les sessions et changer les identifiants bancaires et crypto des utilisateurs touchés.
* Désinstaller les applications compromises et réinitialiser les appareils si un spyware est confirmé.
* Retirer les packages PHP infectés des environnements de production et reconstruire les images.
* Bloquer les domaines et liens d'abonnement frauduleux identifiés au niveau DNS/proxy.

#### Phase 4 — Activités post-incident

* Documenter les applications, packages et indicateurs observés et alimenter la base de connaissances.
* Renforcer les contrôles de revue de code et de dépendances avant mise en production.
* Mettre à jour les politiques BYOD/MDM et les procédures de réponse mobile.
* Évaluer les pertes financières et les obligations de notification aux clients.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les applications installées correspondant aux leurres décrits (faux Play Protect, FomoPeek, thèmes de clavier).
* Rechercher les accès anormaux aux portefeuilles crypto et aux notes contenant des phrases de récupération.
* Rechercher les requêtes sortantes vers des C2 pilotés par LLM ou des endpoints d'abonnement.
* Auditer les dépôts Composer pour des versions altérées ou des dépendances inconnues.
* Corréler les signalements d'abonnements non sollicités avec les installations d'applications récentes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1417** | Capture d'entrées sur mobile (interception de codes de confirmation, vol de données bancaires) |
| **T1412** | Capture de messages SMS (codes de confirmation, données personnelles) |
| **T1409** | Accès aux données applicatives stockées (trousseau, portefeuilles crypto, phrases de récupération) |
| **T1474** | Compromission de la chaîne d'approvisionnement logicielle (packages PHP Packagist infectés) |
| **T1204** | Exécution par l'utilisateur (installation d'applications leurres, certificats développeur) |

---

### Sources

* [https://securelist.com/malware-report-q3-2026-mobile-statistics/121844/](https://securelist.com/malware-report-q3-2026-mobile-statistics/121844/)


---

<div id="comment-exporter-les-journaux-de-cortex-xdr-cortex-xsiam-limacharlie-et-amazon-security-lake"></div>

## Comment exporter les journaux de Cortex XDR, Cortex XSIAM, LimaCharlie et Amazon Security Lake

### Résumé

Quatre guides pratiques publiés par SOC Prime détaillent l'export de télémétrie depuis quatre plateformes de sécurité. Pour Cortex XDR, l'export passe par les API XQL : start_xql_query renvoie un identifiant d'exécution, get_query_results retourne jusqu'à 1 000 résultats en ligne, et get_query_results_stream prend le relais au-delà ; l'authentification utilise l'en-tête Authorization pour la clé et x-xdr-auth-id pour son identifiant, avec un dataset principal xdr_data (agent_hostname, event_type, action_process_image_command_line, actor_process_image_name). Cortex XSIAM réutilise les mêmes API XQL mais avec des datasets bruts de type <vendor>_<product>_raw (ex. fortinet_fortigate_raw) où la ligne d'origine est conservée dans _raw_log, le modèle normalisé XDM étant disponible en alternative. LimaCharlie s'exporte via la CLI (pip install limacharlie, authentification par OID et clé API) avec des requêtes LCQL (limacharlie search run) en sortie JSON, ou en continu via des Outputs vers S3, Google Cloud Storage, SIEM ou webhook ; la rétention Insight est d'un an par défaut et les requêtes sont facturées au volume scanné. Amazon Security Lake stocke les données en Parquet au schéma OCSF dans S3 et ne permet pas le téléchargement direct : il faut interroger via Athena avec une instruction UNLOAD au format JSON, les tables étant dans la base Glue amazon_security_lake_glue_db_<region> et partitionnées par region, accountid et eventday. Les quatre articles mentionnent enfin l'upload des fichiers obtenus dans l'outil LogTotal (logtotal[.]com) pour sanitation et investigation gratuite, et listent les erreurs fréquentes (401, licence, quota, troncature à 1 000 résultats, permissions Lake Formation, préfixe S3 non vide, stockage froid).

---

### Analyse opérationnelle

Ces procédures constituent une base directement réutilisable pour les équipes SOC/DFIR qui doivent extraire de la télémétrie vers un laboratoire d'analyse, un data lake ou un outil de chasse. Points d'attention techniques : la limite de 1 000 résultats en ligne impose systématiquement le recours au stream sous peine de perte silencieuse de données ; le parallélisme est plafonné à quatre requêtes API XQL ; les requêtes Athena sans filtre sur la partition eventday génèrent des coûts de scan importants ; les requêtes LCQL sont facturées à la donnée scannée, d'où l'intérêt des dry runs. La distinction entre données brutes (_raw_log, lignes OCSF) et données normalisées (XDM) conditionne la fidélité de l'investigation : pour l'analyse forensique, privilégier le brut ; pour la corrélation multi-sources, le normalisé. Sur le plan de la sécurité interne, ces mêmes API constituent une surface d'exfiltration : une clé API à privilège de requête permet de vider des mois de télémétrie endpoint (lignes de commande, noms d'hôtes, journaux Windows, flux réseau). Il est donc indispensable de journaliser les appels d'export, de restreindre les rôles, de rotationner les clés et de surveiller la création d'Outputs ou d'abonnements persistants. Enfin, l'upload de télémétrie contenant des données personnelles ou sensibles vers un service tiers doit être encadré (sanitation, base légale, minimisation).

---

### Implications stratégiques

La standardisation des exports de télémétrie devient un enjeu de souveraineté et de maîtrise du risque : plus les données de sécurité sont centralisées dans des plateformes SaaS (XSIAM, Security Lake), plus la capacité à les extraire rapidement détermine l'autonomie d'investigation d'une organisation, notamment en cas de changement de fournisseur ou de fin de contrat. Le cas XSIAM est emblématique : la plateforme a absorbé une partie des clients QRadar SaaS après l'opération de 2024, ce qui pose la question de la réversibilité et de la portabilité des historiques de logs. La normalisation OCSF d'Amazon Security Lake et le modèle XDM de Palo Alto traduisent une tendance de fond à l'unification des schémas, favorable à l'interopérabilité mais créant un point de dépendance fort vis-à-vis des hypervendeurs cloud. Pour les décideurs, ces guides rappellent que la valeur d'un SOC repose autant sur la qualité et la rétention de la télémétrie que sur les règles de détection : la rétention d'un an chez LimaCharlie ou le stockage froid à coût maîtrisé deviennent des critères d'architecture. Enfin, la publication de ce type de contenu par un éditeur de détection illustre la concurrence sur le terrain de la « detection as code » et des plateformes d'investigation, où l'exportabilité des données est utilisée comme argument commercial.

---

### Recommandations

* Documenter et versionner les requêtes d'export (XQL, LCQL, Athena UNLOAD) dans un dépôt interne avec les filtres de partition et de temps obligatoires.
* Créer des clés API dédiées par usage, à privilège minimal, avec rotation trimestrielle et alerting sur les erreurs 401 et les pics de requêtes.
* Toujours utiliser get_query_results_stream au-delà de 1 000 résultats et vérifier la complétude des exports (nombre de lignes attendu vs obtenu).
* Surveiller la création d'Outputs LimaCharlie et d'abonnés Amazon Security Lake comme des vecteurs d'exfiltration persistants.
* Encadrer contractuellement et techniquement tout upload de télémétrie vers un service tiers : sanitation, minimisation, base légale, journalisation.
* Prévoir une stratégie de réversibilité (portabilité des logs, conservation d'un historique brut) pour limiter la dépendance à un fournisseur SIEM/EDR.
* Maîtriser les coûts : filtrer sur eventday dans Athena, faire des dry runs LCQL, surveiller les quotas XQL et le recours au stockage froid.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les sources de télémétrie disponibles (EDR Cortex XDR, plateforme XSIAM, capteurs LimaCharlie, Amazon Security Lake) et documenter pour chacune le dataset, le schéma et la rétention (xdr_data, <vendor>_<product>_raw, Insight 1 an, tables Glue/OCSF).
* Créer des clés API dédiées à l'export, à privilège minimal (rôle autorisé à exécuter des requêtes XQL / LCQL, SELECT Lake Formation), avec rotation planifiée et stockage dans un coffre de secrets.
* Vérifier les prérequis de licence et de quota (Cortex XDR Pro pour les API XQL, facturation LCQL à la donnée scannée, coût Athena au volume scanné) et définir des seuils d'alerte budgétaire.
* Standardiser le format de sortie d'investigation (JSONL) et préparer une chaîne de sanitation/hachage des données sensibles avant tout partage externe ou upload vers un outil tiers.
* Documenter les procédures de secours en cas d'indisponibilité des API (export via Outputs S3/GCS, UNLOAD Athena planifié, export d'incidents et d'alertes via API dédiées).

#### Phase 2 — Détection et analyse

* Contrôler l'usage des API d'export (start_xql_query, get_query_results, get_query_results_stream, limacharlie search run, Athena UNLOAD) : volume de requêtes, parallélisme (max 4 requêtes API XQL), pics hors horaires de travail.
* Surveiller les erreurs d'authentification 401 sur les endpoints d'export, signe possible de clé compromise, expirée ou d'un identifiant mal utilisé (inversion clé / x-xdr-auth-id).
* Détecter les requêtes anormalement larges (absence de filtre timeframe, eventday ou sélecteur de capteur) pouvant indiquer une exfiltration massive de télémétrie.
* Alerter sur la création de nouveaux Outputs LimaCharlie (S3, GCS, webhook, SIEM) ou de nouveaux abonnés Security Lake, vecteurs de sortie persistants de données.
* Journaliser et corréler les accès aux buckets S3 d'export Athena et aux préfixes de destination, y compris les tentatives d'écriture sur préfixe non vide.

#### Phase 3 — Confinement, éradication et récupération

* En cas de suspicion de compromission d'une clé API, révoquer immédiatement la clé et son ID, puis recréer un accès à privilège minimal.
* Suspendre les Outputs et abonnements non légitimes, et bloquer les destinations réseau (S3, GCS, webhook) non référencées dans la baseline.
* Restreindre par politique IAM/Lake Formation et par filtrage réseau les adresses autorisées à appeler les API d'export.
* Isoler les jeux de données exportés contenant des données sensibles, en limiter la diffusion et déclencher la procédure de notification interne si une fuite est confirmée.
* Conserver les journaux d'audit des plateformes (CloudTrail, audit logs LimaCharlie, logs XSIAM) dans un stockage immuable pour l'investigation.

#### Phase 4 — Activités post-incident

* Revoir les rôles et permissions des clés API d'export, appliquer le principe du moindre privilège et une rotation systématique après incident.
* Mettre à jour la documentation des procédures d'export et les runbooks associés avec les enseignements de l'incident.
* Recalculer les coûts et quotas consommés (XQL, LCQL, Athena) pour détecter un usage abusif résiduel.
* Renforcer la sensibilisation des équipes SOC sur la manipulation de télémétrie sensible et les risques de fuite via exports.
* Planifier un exercice de restauration/rejeu des données exportées pour valider la chaîne d'investigation forensique.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux d'audit des plateformes les requêtes d'export initiées par des comptes de service inattendus ou depuis des adresses IP inhabituelles.
* Traquer les requêtes XQL/LCQL/Athena ciblant des hôtes critiques ou des plages temporelles larges sans filtre de partition.
* Corréler les exports massifs avec des événements de création de clé API, de modification de rôle ou d'ajout d'Output dans les 24 heures précédentes.
* Examiner les fichiers de sortie (JSONL, _raw_log) pour détecter des artefacts malveillants antérieurs non traités, en s'appuyant sur les règles de détection mappées MITRE ATT&CK.
* Vérifier l'intégrité et la complétude des exports par rapport aux périodes attendues afin d'identifier des suppressions ou des trous de journalisation.

---

### Sources

* [https://socprime.com/blog/how-to-export-cortex-xdr-logs/](https://socprime.com/blog/how-to-export-cortex-xdr-logs/)
* [https://socprime.com/blog/how-to-export-cortex-xsiam-logs/](https://socprime.com/blog/how-to-export-cortex-xsiam-logs/)
* [https://socprime.com/blog/how-to-export-limacharlie-logs/](https://socprime.com/blog/how-to-export-limacharlie-logs/)
* [https://socprime.com/blog/how-to-export-amazon-security-lake-logs/](https://socprime.com/blog/how-to-export-amazon-security-lake-logs/)


---

<div id="kongtuke-clickfix-sen-prend-a-un-tresor-canadien-canada-dry"></div>

## KongTuke ClickFix s'en prend à un trésor canadien : Canada Dry

### Résumé

Le 10 novembre 2026, quatre sites de boissons canadiennes appartenant à la même société mère — canadadry[.]ca, mottsclamato[.]ca, drinknestea[.]ca et hydratewithcore[.]com — diffusaient le loader KongTuke. Trois d'entre eux servent le loader depuis le chemin /asset-cache/fjs sur leur propre domaine : un plugin WordPress planté récupère le script depuis le serveur de l'opérateur, de sorte que le navigateur du visiteur ne communique qu'avec le site de la marque. À chaque chargement de page, le loader envoie à l'opérateur les cookies lisibles par script et toute valeur de stockage portant un nom de type token (token, jwt, auth, session, csrf, etc.), et ce avant tout contrôle. Les visiteurs acceptés par le serveur reçoivent une fausse page Cloudflare « Performing security verification » ; la commande ClickFix copiée exécute `ftp | cmd` dans une fenêtre minimisée. L'hôte FTP est passé de report-ftp[.]wiki à yelahaye[.]surf dans l'après-midi du 10 novembre. hydratewithcore[.]com charge son script depuis battaglia[.]lol via une balise correspondant au plugin « Web Media Optimizer » (wm.zip). L'activité est antérieure : des scans publics montrent Mott's Clamato et Nestea chargeant KongTuke depuis monteiro[.]click le 17 juillet 2026 ; Core est passé par quatre hôtes externes depuis septembre ; Canada Dry était propre le 16 juillet et a servi /asset-cache/fjs pour la première fois le 29 octobre.

---

### Analyse opérationnelle

La chaîne d'attaque combine deux effets : un vol silencieux de jetons de session (cookies, JWT, CSRF) à chaque visite, permettant une prise de contrôle de comptes clients ou administrateurs sans mot de passe, et un leurre ClickFix qui aboutit à l'exécution d'une commande Windows sur le poste du visiteur. Le fait que le loader soit servi depuis le domaine de la marque rend le filtrage réputationnel classique inefficace : seuls la surveillance d'intégrité web, l'analyse des balises injectées et la détection comportementale endpoint sont discriminantes. Côté SOC, les points de détection prioritaires sont : requêtes vers /asset-cache/fjs, exécution de ftp.exe en pipe vers cmd.exe, fenêtres minimisées lancées au démarrage d'un navigateur, connexions sortantes vers des domaines récents en .surf/.lol/.click/.wiki, et modifications non planifiées de wp-content/plugins. La réponse doit inclure la révocation massive des sessions et tokens, la purge CDN, le retrait du plugin compromis et l'isolement des postes ayant exécuté la commande. La rotation rapide d'infrastructure (changement d'hôte FTP en quelques heures, quatre hébergeurs successifs pour Core) impose des détections fondées sur le comportement plutôt que sur des IOC figés.

---

### Implications stratégiques

Cette campagne illustre la transformation des sites de marque grand public en vecteur d'attaque de supply chain web : l'attaquant n'a pas besoin de compromettre l'infrastructure de la victime finale, il exploite la confiance accordée au domaine de la marque. Pour les groupes agroalimentaires et de grande consommation, l'enjeu dépasse la sécurité IT : il touche à la réputation, à la conformité (cookies et consentement, RGPD) et à la responsabilité contractuelle vis-à-vis des agences web et des régisseurs de tags. La persistance de l'activité depuis juillet 2026 sur plusieurs marques du même groupe suggère une reconnaissance ciblée du secteur et une capacité de réinfection rapide après nettoyage. Les directions doivent considérer la surface web externe comme un actif critique à part entière, avec inventaire, contrôle des tiers et supervision continue.

---

### Recommandations

* Auditer immédiatement tous les sites WordPress du groupe : plugins installés, comptes administrateurs, intégrité des fichiers et balises injectées.
* Déployer une surveillance d'intégrité de fichiers et une alerte sur la création de répertoires de type /asset-cache/ ou de scripts non référencés.
* Bloquer ftp.exe et les exécutions en pipe cmd/powershell sur les postes utilisateurs, et journaliser les clés RunMRU.
* Révoquer les sessions et jetons applicatifs exposés et imposer une réauthentification des comptes clients sensibles.
* Ajouter les domaines report-ftp[.]wiki, yelahaye[.]surf, battaglia[.]lol et monteiro[.]click aux listes de blocage DNS/proxy et aux règles de détection.
* Imposer une revue de sécurité et une clause de notification rapide aux prestataires web, CDN et tag managers.
* Sensibiliser les collaborateurs et les clients au leurre ClickFix « vérification de sécurité » et à la copie de commandes dans le presse-papiers.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les sites web de marque et portails marketing (y compris les sites de pays) et identifier les CMS, plugins et tags managers utilisés.
* Mettre en place une surveillance d'intégrité de fichiers sur wp-content/plugins, wp-content/themes et les répertoires de cache (ex. /asset-cache/).
* Configurer l'alerte SIEM sur l'apparition de chemins suspects du type /asset-cache/fjs et sur les requêtes sortantes vers des domaines récents (.surf, .lol, .click, .wiki).
* Bloquer au niveau proxy/DNS les TLD à faible réputation et restreindre l'usage de ftp.exe sur les postes utilisateurs via AppLocker/WDAC.
* Sensibiliser les équipes marketing/web à l'interdiction d'installer des plugins non validés et formaliser un processus de revue de code des tags tiers.

#### Phase 2 — Détection et analyse

* Rechercher dans les logs web des requêtes GET vers /asset-cache/fjs sur les domaines de marque et corréler avec les IP clientes.
* Détecter côté endpoint l'exécution de ftp.exe en pipe vers cmd.exe, en particulier lancé depuis une fenêtre minimisée ou depuis un parent explorer.exe/rundll32.exe.
* Inspecter les clés RunMRU et l'historique du presse-papiers pour identifier des commandes copiées de type ClickFix.
* Rechercher des connexions sortantes vers report-ftp[.]wiki, yelahaye[.]surf, battaglia[.]lol et monteiro[.]click dans les logs proxy, DNS et NetFlow.
* Vérifier l'apparition de balises ou de scripts non autorisés dans les pages (comparaison avec une baseline HTML) et l'installation de plugins non référencés (ex. « Web Media Optimizer » / wm.zip).

#### Phase 3 — Confinement, éradication et récupération

* Retirer immédiatement le plugin WordPress compromis et le script injecté, puis purger les caches CDN et navigateurs.
* Révoquer l'ensemble des sessions et tokens applicatifs susceptibles d'avoir été exfiltrés (cookies, JWT, CSRF) et forcer la réauthentification des comptes exposés.
* Isoler les postes utilisateurs ayant exécuté la commande ClickFix et lancer une collecte forensique (mémoire, RunMRU, artefacts de persistance).
* Bloquer les domaines et URL IOC au niveau DNS, proxy et pare-feu, et ajouter les détections correspondantes au SIEM/EDR.
* Notifier l'hébergeur/CDN et la société mère pour les quatre sites concernés, et publier un message d'information aux clients si des sessions sont compromises.

#### Phase 4 — Activités post-incident

* Réaliser une revue post-incident du processus de déploiement web et du contrôle des plugins/tiers (chaîne de build, revue de code, MFA sur l'administration WordPress).
* Auditer les comptes administrateurs du CMS, rotation des secrets et des clés API, et vérifier l'absence de comptes fantômes.
* Évaluer l'exposition des données personnelles (cookies de session, identifiants) et statuer sur les obligations de notification RGPD.
* Mettre à jour les règles de détection avec les nouveaux domaines et chemins observés et intégrer les IOC au threat intelligence platform.
* Renforcer contractuellement les exigences de sécurité auprès des agences web et prestataires de tag management.

#### Phase 5 — Threat Hunting (proactif)

* Chasser rétroactivement (juillet 2026 → aujourd'hui) les chargements de monteiro[.]click, battaglia[.]lol et report-ftp[.]wiki dans les logs historiques proxy/DNS.
* Rechercher des variantes du chemin /asset-cache/ et d'autres noms de répertoires de camouflage sur l'ensemble du parc web.
* Traquer les schémas ClickFix génériques : pages de fausse vérification Cloudflare, copie automatique dans le presse-papiers, exécution de commandes ftp/curl/powershell en fenêtre minimisée.
* Corréler les connexions FTP sortantes inhabituelles avec les journaux d'authentification pour détecter un éventuel mouvement latéral ou un vol de données.
* Partager les IOC et TTP avec les CERT sectoriels et les pairs du secteur agroalimentaire/retail.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `canadadry[.]ca` | High |
| DOMAIN | `mottsclamato[.]ca` | High |
| DOMAIN | `drinknestea[.]ca` | High |
| DOMAIN | `hydratewithcore[.]com` | High |
| DOMAIN | `report-ftp[.]wiki` | High |
| DOMAIN | `yelahaye[.]surf` | High |
| DOMAIN | `battaglia[.]lol` | High |
| DOMAIN | `monteiro[.]click` | High |
| URL | `hxxps://canadadry[.]ca/asset-cache/fjs` | Medium |
| URL | `hxxps://mottsclamato[.]ca/asset-cache/fjs` | Medium |
| URL | `hxxps://drinknestea[.]ca/asset-cache/fjs` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1189** | Drive-by Compromise : injection du loader dans des sites légitimes de marques de boissons |
| **T1204.004** | Malicious Copy and Paste : leurre ClickFix « Performing security verification » copiant une commande dans le presse-papiers |
| **T1059.003** | Windows Command Shell : exécution de `ftp \| cmd` dans une fenêtre minimisée |
| **T1539** | Steal Web Session Cookie : exfiltration des cookies lisibles par script et des valeurs de stockage de type token/jwt/session/csrf |
| **T1505.003** | Web Shell / plugin WordPress planté servant de relais vers le serveur de l'opérateur |
| **T1102** | Web Service : usage de domaines et d'hébergements légers (yelahaye[.]surf, battaglia[.]lol, monteiro[.]click) comme infrastructure tournante |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1xssqyr/kongtuke_clickfix_comes_for_a_canadian_treasure/](https://www.reddit.com/r/blueteamsec/comments/1xssqyr/kongtuke_clickfix_comes_for_a_canadian_treasure/)


---

<div id="iranul-acuzat-de-atacul-asupra-frigiderelor-din-franta-o-amenintare-iraniana-ar-fi-pus-si-armata-sua-in-alerta"></div>

## 🇮🇷#Iranul, acuzat de atacul asupra frigiderelor din 🇫🇷#Franța. O amenințare 🇮🇷#Iraniană ar fi pus și armata 🇺🇸#SUA în alertă.

### Résumé

La France a accusé officiellement l'Iran, le 10 novembre 2026, pour l'attaque informatique menée dans la nuit du 11 au 12 octobre contre les systèmes de réfrigération d'environ 700 magasins sur le territoire national. Selon le ministre des Affaires étrangères Jean-Noël Barrot, le Corps des Gardiens de la Révolution islamique est responsable de l'opération, qualifiée d'« attaque de sabotage de grande ampleur » et d'« agression majeure ». Les attaquants ont provoqué la surchauffe des vitrines réfrigérées et désactivé les alertes, entraînant d'importantes pertes alimentaires et une vingtaine d'incendies. Paris a convoqué l'ambassadeur iranien, prépare des sanctions avec ses partenaires européens et le parquet a demandé des mandats d'arrêt internationaux. Début novembre, une seconde vague a touché plus de 100 unités dans 11 pays européens ; en France, trois centres de la banque nationale de sang ont été visés le 2 novembre, le personnel parvenant à déplacer les poches de sang. Parallèlement, l'US Air Force a déplacé 12 avions de transport de la base de Mildenhall (Royaume-Uni) vers l'Allemagne et l'Espagne après une menace iranienne, tandis que Donald Trump a déclaré que la guerre avec l'Iran était « pratiquement terminée ».

---

### Analyse opérationnelle

L'attaque cible des équipements OT/IoT de froid commercial faiblement protégés : interfaces d'administration exposées, comptes par défaut, absence de segmentation entre le réseau magasin et les systèmes de supervision. Le point le plus critique n'est pas la modification des consignes de température mais la désactivation des alarmes, qui prive les exploitants de leur capacité de détection et transforme un incident réversible en sinistre matériel (incendies, pertes de stocks). Pour les équipes SOC/OT, la détection doit s'appuyer sur la surveillance des écritures de paramètres, des changements de configuration des automates et des journaux d'administration, ainsi que sur une supervision physique redondante des températures. La réponse exige une capacité de bascule en mode manuel, l'isolation réseau des équipements et la vérification physique des alarmes. La seconde vague européenne et l'extension aux centres de la chaîne du froid sanguine indiquent une campagne en cours, non un incident isolé, avec un risque de réitération sur d'autres enseignes et infrastructures civiles.

---

### Implications stratégiques

Il s'agit du premier sabotage informatique de grande ampleur attribué publiquement à un État sur le territoire français, ce qui fait franchir un seuil dans la conflictualité cyber : la cible n'est plus l'espionnage ou la donnée mais le matériel et la sécurité physique des personnes. Les conséquences sont multiples : escalade diplomatique (convocation d'ambassadeur, sanctions européennes, mandats d'arrêt internationaux), durcissement réglementaire attendu sur la sécurité des objets connectés et des infrastructures civiles (NIS2, Cyber Resilience Act), et pression accrue sur les assureurs et les directions des risques. Pour les secteurs du retail, de l'agroalimentaire et de la santé, la chaîne du froid devient une dépendance critique à traiter au niveau du conseil d'administration, avec des enjeux de continuité d'activité, de sécurité alimentaire et de confiance du public. L'articulation entre cyber et posture militaire (déplacement d'aéronefs, alertes) montre que les opérations cyber s'inscrivent désormais dans un rapport de force géopolitique global.

---

### Recommandations

* Recenser et cartographier en urgence tous les équipements de froid connectés et leurs accès distants, puis fermer toute exposition Internet non indispensable.
* Segmenter les réseaux OT/IoT du froid et déployer une supervision de température indépendante du réseau informatique.
* Supprimer les comptes et mots de passe par défaut, activer le MFA sur les interfaces d'administration et journaliser les changements de configuration.
* Tester la capacité de bascule en mode manuel et les procédures de sauvegarde des denrées périssables et des produits de santé.
* Étendre la surveillance aux chaînes du froid sanguine et pharmaceutique, identifiées comme cibles de la seconde vague.
* Établir un canal de remontée rapide vers les autorités (ANSSI, CERT sectoriels) et participer aux partages d'information sectoriels.
* Intégrer le scénario de sabotage étatique dans les exercices de crise et les plans de continuité d'activité.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les équipements de réfrigération et de froid alimentaire connectés (automates, passerelles IoT, supervision) et leur exposition Internet.
* Segmenter les réseaux OT/IoT du froid en zones dédiées avec filtrage strict vers l'IT et interdiction d'accès direct depuis Internet.
* Vérifier l'existence de comptes par défaut, de mots de passe partagés et l'absence de MFA sur les interfaces d'administration des équipements.
* Définir des seuils d'alerte physiques (température, surchauffe, consommation) indépendants du système de supervision logiciel.
* Préparer un plan de continuité : groupes froids de secours, relocalisation des denrées périssables, procédures pour les produits de santé à chaîne du froid.

#### Phase 2 — Détection et analyse

* Surveiller les changements de consignes de température, les écritures Modbus/BACnet anormales et les commandes d'arrêt de compresseurs.
* Détecter la suppression ou la désactivation des alarmes de supervision (journaux d'administration, changements de configuration).
* Analyser les connexions VPN/administrateur vers les réseaux OT depuis des adresses IP étrangères ou hors horaires d'exploitation.
* Corréler les incidents physiques (surchauffe, odeurs de brûlé, départs de feu) avec les journaux réseau pour identifier une action malveillante.
* Surveiller les tentatives d'authentification en échec et les scans sur les interfaces exposées des équipements de froid.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les équipements compromis du réseau et basculer la supervision en mode manuel/local.
* Réactiver et vérifier physiquement les alarmes de température et de sécurité incendie sur l'ensemble des sites.
* Réinitialiser les identifiants des équipements OT/IoT, révoquer les accès distants et fermer les flux non nécessaires.
* Déployer des équipes de contrôle physique des vitrines et des chambres froides, en priorité pour les produits de santé et périssables.
* Conserver les journaux et images des équipements avant remise en service pour l'enquête et l'attribution.

#### Phase 4 — Activités post-incident

* Reconstruire une architecture OT/IoT segmentée avec passerelles supervisées, MFA et journalisation centralisée.
* Mettre en place une supervision redondante des températures indépendante du réseau informatique.
* Réviser les plans de continuité d'activité et les assurances au regard des pertes de denrées et des dommages matériels.
* Coordonner avec les autorités nationales (ANSSI, parquet, CERT) et documenter les éléments d'attribution.
* Renforcer la veille sur les menaces étatiques visant les chaînes du froid et les infrastructures civiles.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts de persistance sur les passerelles IoT et automates (comptes créés, tâches planifiées, firmwares modifiés).
* Analyser les journaux historiques pour identifier des accès préparatoires dans les semaines précédant l'attaque (reconnaissance, scans, connexions VPN).
* Traquer les mêmes TTP sur les sites d'autres pays européens touchés par la seconde vague (11 pays, plus de 100 unités).
* Vérifier les centres de la chaîne du froid sanguine et les entrepôts pharmaceutiques pour des tentatives similaires.
* Partager les indicateurs comportementaux avec les fédérations sectorielles et les CERT.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T0813** | Denial of Control : mise hors service des vitrines réfrigérées de centaines de magasins |
| **T0836** | Modify Parameter : modification des consignes de température provoquant la surchauffe des équipements |
| **T0879** | Damage to Property : dégradation matérielle et incendies consécutifs à la surchauffe |
| **T1562.001** | Impair Defenses: Disable or Modify Tools : désactivation des alertes de supervision des systèmes de réfrigération |
| **T1078** | Valid Accounts : accès probable via comptes ou interfaces d'administration exposés des équipements OT/IoT |

---

### Sources

* [https://stirileprotv.ro/stiri/international/iranul-acuzat-ca-a-pus-la-cale-atacul-cibernetic-care-a-scos-din-functiune-frigiderele-din-700-de-magazine-din-franta.html](https://stirileprotv.ro/stiri/international/iranul-acuzat-ca-a-pus-la-cale-atacul-cibernetic-care-a-scos-din-functiune-frigiderele-din-700-de-magazine-din-franta.html)


---

<div id="publications-sur-des-sites-de-fuite-de-ransomware-incransom-bravox-et-pixelleaks-revendiquent-des-victimes-dans-les-secteurs-juridique-de-la-sante-manufacturier-et-du-transport"></div>

## Publications sur des sites de fuite de ransomware : incransom, Bravox et PixelLeaks revendiquent des victimes dans les secteurs juridique, de la santé, manufacturier et du transport

### Résumé

Le 10 novembre 2026, plusieurs publications sur des sites de fuite de groupes de rançongiciel ont été recensées. Le groupe incransom revendique la victime « jnattorney », un cabinet juridique américain. Le groupe Bravox revendique l'AWO Bundesverband, organisation allemande du secteur de la santé. Le groupe PixelLeaks revendique trois victimes : un fabricant indien de bornes à raccordement électrique (secteur industriel), une seconde entité du même secteur industriel, et une société de thérapies par protéines plasmatiques (biopharma, secteur santé). Par ailleurs, la page de suivi du groupe « inc ransom » référence une victime supplémentaire, Roane Transportation Services, dans le secteur du transport, avec un compteur indiquant 0 victime en ligne sur 13.

---

### Analyse opérationnelle

Ces revendications, prises isolément, ne constituent pas une preuve de compromission : elles doivent être traitées comme des signaux de veille à corréler avec les alertes internes et les informations des prestataires. L'intérêt opérationnel réside dans la sectorisation : santé (organisation faîtière allemande, biopharma), industrie manufacturière et transport, secteurs où l'indisponibilité des systèmes a un impact direct sur la production et la chaîne logistique. Pour un SOC, la priorité est de vérifier si l'organisation ou l'un de ses fournisseurs critiques apparaît sur ces sites, d'évaluer l'exposition des données revendiquées et de déclencher une chasse ciblée sur les TTP de double extorsion (exfiltration préalable, suppression des sauvegardes, chiffrement). La multiplication de groupes de niche (Bravox, PixelLeaks) aux côtés d'acteurs établis (incransom) complique l'attribution et impose une surveillance multi-sources.

---

### Implications stratégiques

La fragmentation de l'écosystème rançongiciel en groupes de niche, souvent alignés sur des secteurs précis, accroît la pression sur les organisations de taille intermédiaire qui disposent de moins de ressources défensives. Le ciblage répété de la santé — y compris des fédérations et organisations faîtières dont dépendent de nombreux établissements — illustre un risque systémique par effet de contagion via les prestataires et les réseaux partagés. Pour les directions, ces revendications doivent alimenter la priorisation des investissements : sauvegardes immuables, segmentation, gestion des accès tiers et préparation à la crise. La publication de données de santé ou de propriété industrielle expose par ailleurs à des risques réglementaires (RGPD, secret des affaires) et à une perte de confiance durable des patients et des clients.

---

### Recommandations

* Mettre en place une veille automatisée des sites de fuite et des canaux de revendication, avec alerting sur les noms de l'organisation et de ses fournisseurs.
* Vérifier l'existence de sauvegardes immuables hors ligne et tester la restauration des systèmes critiques.
* Renforcer le MFA et la segmentation sur les accès distants et les comptes à privilèges.
* Auditer la sécurité des prestataires critiques (santé, industrie, transport) et intégrer des clauses de notification d'incident.
* Préparer un plan de notification RGPD et sectoriel en cas de fuite de données personnelles ou de santé.
* Réaliser un exercice de simulation de crise ransomware incluant la communication externe.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Assurer des sauvegardes hors ligne immuables et tester régulièrement les restaurations complètes.
* Segmenter les réseaux, imposer le MFA sur les accès distants et les comptes à privilèges, et inventorier les services exposés.
* Mettre en place une veille automatisée sur les sites de fuite (incransom, Bravox, PixelLeaks et autres) pour détecter une divulgation de nom de victime.
* Préparer un plan de communication de crise et un dispositif juridique (notification CNIL, RGPD, autorités sectorielles).
* Cartographier les données sensibles et les dépendances fournisseurs pour évaluer rapidement l'impact d'une fuite.

#### Phase 2 — Détection et analyse

* Surveiller les alertes EDR sur les comportements de chiffrement massif, la suppression de clichés instantanés et la désactivation des journaux.
* Détecter les exfiltrations volumineuses vers des services cloud ou des serveurs FTP/SFTP inconnus.
* Analyser les connexions VPN et les authentifications privilégiées atypiques (horaires, géolocalisation, volume).
* Surveiller les sites de fuite et les canaux Telegram/forums pour identifier une revendication concernant l'organisation ou ses prestataires.
* Corréler les alertes de sécurité avec les communications d'extorsion reçues par messagerie ou courriel.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments compromis et désactiver les comptes à privilèges suspectés.
* Couper les accès distants (VPN, RDP) et réinitialiser les secrets d'authentification (comptes de service, clés API, Kerberos).
* Préserver les preuves (images disque, journaux, échantillons de rançongiciel) avant toute remédiation.
* Activer la cellule de crise : direction, juridique, communication, assurance cyber et éventuellement négociateur.
* Évaluer l'exposition des données personnelles et de santé pour anticiper les obligations de notification.

#### Phase 4 — Activités post-incident

* Reconstruire les systèmes à partir de sauvegardes saines et vérifier l'absence de persistance avant remise en production.
* Mener une analyse post-incident du vecteur d'accès initial et corriger les vulnérabilités exploitées.
* Renforcer la gouvernance des accès tiers et la surveillance des prestataires critiques.
* Mettre à jour les procédures de notification et la communication aux patients, clients et partenaires.
* Réaliser un exercice de crise ransomware avec la direction et tester le plan de continuité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts des groupes incransom, Bravox et PixelLeaks (binaires, scripts, noms de fichiers, notes de rançon) sur l'ensemble du parc.
* Analyser les journaux historiques pour identifier une reconnaissance ou un accès initial plusieurs semaines avant la revendication.
* Traquer les mouvements latéraux via RDP, SMB, WMI et les créations de comptes non autorisés.
* Vérifier si des données de l'organisation apparaissent sur les sites de fuite ou dans des ventes de données.
* Partager les indicateurs avec les CERT sectoriels et les pairs du secteur santé et industrie.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact : chiffrement des systèmes des victimes |
| **T1490** | Inhibit System Recovery : suppression des sauvegardes pour empêcher la restauration |
| **T1657** | Financial Theft : extorsion par double voilement (chiffrement + publication de données) |
| **T1567.002** | Exfiltration to Cloud Storage : exfiltration préalable des données publiées sur les sites de fuite |
| **T1078** | Valid Accounts : accès initial fréquent via comptes valides, VPN ou services exposés |

---

### Sources

* [https://infosec.exchange/@CTI_FYI/117594441257346686](https://infosec.exchange/@CTI_FYI/117594441257346686)
* [https://www.ransomlook.io//group/inc%20ransom](https://www.ransomlook.io//group/inc%20ransom)


---

<div id="sg-sph-media-victime-de-cyberattaques-declare-quaucune-donnee-financiere-client-ni-aucun-acces-na-ete-expose"></div>

## SG : SPH Media victime de cyberattaques ; déclare qu'aucune donnée financière client ni aucun accès n'a été exposé

### Résumé

SPH Media, groupe de médias singapourien, indique avoir été la cible de cyberattaques et affirme qu'aucune donnée financière client ni aucun accès n'a été exposé.

---

### Analyse opérationnelle

L'affirmation d'absence d'exposition doit être vérifiée par des éléments techniques : journaux d'accès aux bases d'abonnés, requêtes anormales, exports massifs. Pour un SOC, l'enjeu est de distinguer une tentative d'intrusion déjouée d'une compromission silencieuse avec exfiltration. Les systèmes de facturation et les bases d'abonnés constituent la cible de valeur ; la surveillance doit porter sur les requêtes volumétriques et les accès hors horaires.

---

### Implications stratégiques

Les groupes média sont des cibles sensibles car ils cumulent bases d'abonnés, données de paiement et positions éditoriales à risque. Une compromission, même sans impact financier confirmé, peut être exploitée pour de la désinformation ou de l'usurpation de contenu. À l'échelle de Singapour, cet incident s'inscrit dans une pression cyber soutenue sur les infrastructures d'information, avec des implications de confiance publique et de continuité éditoriale.

---

### Recommandations

* Renforcer la surveillance des bases d'abonnés et des systèmes de paiement (requêtes volumétriques, exports).
* Imposer le MFA sur tous les accès administratifs et éditoriaux.
* Segmenter les environnements de publication et de facturation.
* Préparer un plan de communication crédible en cas de confirmation d'exposition de données.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les services exposés (portails d'abonnement, API, CMS, régie publicitaire) et les données clients associées.
* Mettre en place une journalisation centralisée et une segmentation entre systèmes éditoriaux et systèmes de facturation.
* Définir les critères de qualification d'un incident comme « significatif » au regard des obligations de notification.
* Préparer des scénarios de communication de crise adaptés à un groupe média à forte audience.

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux bases d'abonnés et aux systèmes de paiement.
* Détecter les tentatives d'exploitation sur les applications web exposées (WAF, journaux applicatifs).
* Analyser les pics d'authentification échouée et les connexions depuis des géographies inhabituelles.
* Corréler les alertes avec les revendications publiées sur les canaux de fuite.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis et couper les accès suspects sans interrompre la diffusion éditoriale critique.
* Révoquer les identifiants exposés et imposer une rotation des secrets applicatifs.
* Bloquer les adresses et domaines malveillants identifiés.
* Activer la cellule de crise et coordonner avec les autorités locales de cybersécurité.

#### Phase 4 — Activités post-incident

* Auditer les contrôles d'accès aux données clients et renforcer le chiffrement au repos.
* Revoir les contrats avec les prestataires et intégrer des clauses de notification d'incident.
* Mettre à jour les procédures de notification et la communication aux abonnés.
* Conduire un exercice de simulation de crise média.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des webshells et des comptes créés hors procédure sur les serveurs web.
* Analyser les journaux de base de données pour détecter des extractions massives.
* Rechercher des traces de persistance sur les postes des équipes éditoriales et techniques.
* Surveiller les places de marché et canaux Telegram pour des données revendiquées SPH Media.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'applications exposées publiquement (vecteur possible) |
| **T1078** | Utilisation de comptes valides pour l'accès aux systèmes |
| **T1567** | Exfiltration de données vers un service externe |

---

### Sources

* [https://databreaches.net/2026/11/10/sg-sph-media-hit-by-cyberattacks-says-no-customer-financial-data-or-access-exposed/](https://databreaches.net/2026/11/10/sg-sph-media-hit-by-cyberattacks-says-no-customer-financial-data-or-access-exposed/)


---

<div id="binance-qualifie-de-tentative-darnaque-la-publication-attribuee-a-shinyhunters"></div>

## Binance qualifie de tentative d'arnaque la publication attribuée à ShinyHunters

### Résumé

Selon l'article, Binance qualifie de tentative d'escroquerie (« scam attempt ») une publication attribuée au groupe ShinyHunters, qui revendiquait une fuite de données.

---

### Analyse opérationnelle

Une revendication non vérifiée de fuite de données crée un risque opérationnel immédiat : afflux de tickets support, tentatives de phishing se réclamant de la fuite, et risque de fraude sur les comptes clients. Le SOC doit traiter la revendication comme un scénario d'ingénierie sociale plutôt que comme une compromission avérée, tout en vérifiant techniquement l'authenticité des échantillons publiés. La réponse publique doit être factuelle pour éviter d'amplifier la rumeur.

---

### Implications stratégiques

Les plateformes crypto sont exposées à une double menace : compromission réelle et instrumentalisation de fausses fuites pour déstabiliser la confiance des utilisateurs ou faciliter des campagnes de phishing. La notoriété de ShinyHunters est utilisée comme signal de crédibilité, ce qui illustre la porosité entre extorsion réelle et escroquerie opportuniste. Pour le secteur, cela renforce la nécessité de mécanismes de vérification indépendants et d'une communication de crise rapide, sous peine d'impact sur la réputation et la valeur de la plateforme.

---

### Recommandations

* Mettre en place une procédure formelle de vérification des revendications de fuite avant toute communication.
* Surveiller les campagnes de phishing exploitant le nom de la plateforme et de l'acteur.
* Renforcer les contrôles anti-fraude et la surveillance des connexions client.
* Partager les indicateurs avec les CERT sectoriels et les échanges sectoriels crypto.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Établir une veille permanente sur les canaux de fuite et les comptes attribués à ShinyHunters.
* Définir une procédure de vérification des revendications de fuite (échantillonnage, empreintes, cohérence).
* Préparer des modèles de communication publique pour démentir une fausse fuite sans amplifier la rumeur.
* Cartographier les données clients critiques et les contrôles d'accès associés.

#### Phase 2 — Détection et analyse

* Analyser les échantillons publiés pour vérifier l'authenticité et l'origine des données.
* Rechercher des accès anormaux aux bases clients et aux systèmes KYC.
* Surveiller les campagnes de phishing ciblant les utilisateurs se réclamant de la fuite.
* Détecter les mentions de la marque sur les forums et places de marché cyber.

#### Phase 3 — Confinement, éradication et récupération

* Publier une position officielle claire et factuelle si la revendication est jugée frauduleuse.
* Renforcer temporairement la surveillance des comptes clients et les contrôles anti-fraude.
* Révoquer préventivement les identifiants ou sessions suspects.
* Alerter les clients sur les risques de phishing exploitant la rumeur.

#### Phase 4 — Activités post-incident

* Documenter l'incident et les indicateurs de la campagne d'escroquerie pour enrichir la threat intelligence.
* Revoir les procédures de vérification des revendications de fuite.
* Renforcer la sensibilisation client face aux fausses fuites utilisées comme appât.
* Partager les indicateurs avec les CERT sectoriels et les pairs du secteur crypto.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'accès aux données clients sur la période de la revendication.
* Analyser les comptes et infrastructures utilisés pour diffuser la fausse fuite.
* Traquer les campagnes de phishing corrélées à la revendication.
* Surveiller les réutilisations ultérieures des mêmes artefacts par d'autres acteurs.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1657** | Extorsion et tentative d'escroquerie via revendication de fuite de données |
| **T1585** | Usurpation d'identité et création de personas pour crédibiliser une revendication |
| **T1598** | Manipulation et ingénierie sociale visant les clients |

---

### Sources

* [https://databreaches.net/2026/11/09/binance-calls-alleged-shinyhunters-post-a-scam-attempt/](https://databreaches.net/2026/11/09/binance-calls-alleged-shinyhunters-post-a-scam-attempt/)


---

<div id="des-donnees-de-patients-de-weill-cornell-saisies-dans-des-outils-dia-sans-autorisation"></div>

## Des données de patients de Weill Cornell saisies dans des outils d'IA sans autorisation

### Résumé

Selon l'article, des données de patients de Weill Cornell ont été saisies dans des outils d'intelligence artificielle sans autorisation.

---

### Analyse opérationnelle

Il s'agit d'un cas typique d'« IA de l'ombre » : des utilisateurs habilités introduisent des données de santé dans des services externes non approuvés, hors du périmètre de contrôle de l'IT. La détection repose sur le CASB, le DLP et l'analyse des flux vers les domaines d'IA générative. La réponse doit être graduée : blocage technique, sensibilisation, et évaluation de l'exposition réelle auprès des fournisseurs concernés.

---

### Implications stratégiques

La donnée de santé est parmi les plus sensibles et son transfert vers des tiers non contractuellement encadrés expose l'établissement à des sanctions réglementaires et à un risque réputationnel majeur. L'adoption rapide des outils d'IA générative par les soignants et chercheurs crée un conflit entre productivité et conformité. Les organisations doivent arbitrer en fournissant des alternatives approuvées plutôt qu'en se limitant à l'interdiction, sous peine de contournements persistants.

---

### Recommandations

* Déployer un CASB/DLP couvrant les services d'IA générative et bloquer les usages non approuvés.
* Fournir une solution d'IA interne ou contractuellement encadrée pour les usages légitimes.
* Former les personnels à la classification des données et aux risques de l'IA de l'ombre.
* Mettre en place une procédure de notification et d'évaluation rapide en cas d'exposition de données patients.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les outils d'IA autorisés et interdits, et formaliser une politique d'usage claire.
* Classifier les données patients et définir les règles de traitement vers des services tiers.
* Déployer une solution CASB/DLP capable de détecter les saisies de données sensibles dans des services d'IA.
* Former les personnels soignants et de recherche aux risques de l'IA de l'ombre.

#### Phase 2 — Détection et analyse

* Détecter les flux réseau et les saisies vers des services d'IA non approuvés (CASB, proxy, DNS).
* Analyser les journaux d'accès aux dossiers patients pour identifier des extractions ou copies inhabituelles.
* Rechercher des données patients dans les journaux de navigateur et les caches locaux.
* Corréler les alertes DLP avec les comptes utilisateurs concernés.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les services d'IA non autorisés au niveau du proxy et du CASB.
* Suspendre ou restreindre les comptes impliqués le temps de l'investigation.
* Supprimer les données téléversées lorsque les fournisseurs le permettent et documenter les démarches.
* Activer la cellule de crise et le juridique pour évaluer les obligations de notification.

#### Phase 4 — Activités post-incident

* Évaluer l'étendue et la nature des données exposées (identifiants patients, données cliniques).
* Mettre à jour la politique d'usage de l'IA et déployer des alternatives approuvées.
* Renforcer la formation et la sensibilisation des équipes.
* Documenter l'incident pour les autorités de protection des données compétentes.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces de téléversement de fichiers contenant des données patients vers des services cloud.
* Analyser les requêtes DNS et les certificats TLS vers des domaines d'IA générative.
* Identifier les comptes ayant accédé massivement aux dossiers patients sur la période concernée.
* Vérifier la présence de données patients dans les partages cloud personnels et les boîtes mail.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration de données vers des services externes (outils d'IA grand public) |
| **T1078** | Utilisation de comptes valides pour saisir des données dans des services non autorisés |
| **T1530** | Accès non autorisé à des données stockées (dossiers patients) |

---

### Sources

* [https://databreaches.net/2026/11/09/weill-cornell-patient-data-entered-into-ai-tools-without-authorization/](https://databreaches.net/2026/11/09/weill-cornell-patient-data-entered-into-ai-tools-without-authorization/)


---

<div id="laustralie-va-introduire-une-obligation-de-signalement-apres-le-piratage-dopenai-pour-lutter-contre-lia-qui-devient-incontrolable"></div>

## L'Australie va introduire une obligation de signalement après le piratage d'OpenAI pour lutter contre l'IA qui « devient incontrôlable »

### Résumé

Selon l'article, l'Australie prévoit d'introduire une obligation de notification obligatoire à la suite d'un piratage visant OpenAI, afin de lutter contre les dérives de l'intelligence artificielle (« going rogue »).

---

### Analyse opérationnelle

L'instauration d'une obligation de notification impose aux organisations utilisant ou fournissant des systèmes d'IA de disposer de capacités de détection et de traçabilité adaptées : journaux d'accès aux modèles, aux jeux de données et aux API, critères de qualification d'un incident IA, et procédures de notification dans les délais. Les équipes SOC doivent anticiper l'extension de leur périmètre de surveillance aux environnements d'inférence et aux dépendances fournisseurs.

---

### Implications stratégiques

Cette évolution réglementaire traduit une tendance de fond : les États considèrent désormais les incidents affectant les systèmes d'IA comme des événements de sécurité nationale nécessitant déclaration. Pour les fournisseurs de modèles et leurs clients, cela implique une pression accrue sur la transparence, la documentation des incidents et la responsabilité contractuelle. Les organisations devront arbitrer entre rapidité d'innovation et conformité, avec un risque de fragmentation réglementaire entre juridictions.

---

### Recommandations

* Anticiper les obligations de notification en documentant dès maintenant les incidents liés à l'IA.
* Étendre la journalisation aux environnements d'inférence, aux API et aux jeux de données d'entraînement.
* Intégrer des clauses de notification d'incident et d'audit dans les contrats avec les fournisseurs d'IA.
* Mettre en place une gouvernance IA associant sécurité, juridique et métiers.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les systèmes d'IA en production et leurs dépendances fournisseurs.
* Définir les critères d'un incident IA significatif et les obligations de notification applicables.
* Établir des canaux de communication avec les régulateurs et les fournisseurs de modèles.
* Former les équipes à la détection d'abus de modèles et de fuites de données d'entraînement.

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux API de modèles et les tentatives d'extraction de données.
* Détecter les comportements de modèle déviants et les jailbreaks répétés.
* Analyser les journaux d'accès aux jeux de données d'entraînement et aux environnements d'inférence.
* Corréler les alertes avec les signalements des fournisseurs.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre les clés d'API et les accès compromis.
* Isoler les environnements d'inférence affectés et limiter les fonctionnalités à risque.
* Notifier le régulateur selon le cadre applicable et documenter la chronologie.
* Communiquer de manière coordonnée avec les parties prenantes.

#### Phase 4 — Activités post-incident

* Réaliser un retour d'expérience sur les causes et les délais de détection.
* Renforcer les contrôles d'accès et la traçabilité des modèles.
* Mettre à jour les procédures de notification et les contrats fournisseurs.
* Contribuer aux travaux réglementaires et aux échanges sectoriels.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des tentatives d'extraction de données d'entraînement et d'abus d'API.
* Analyser les journaux de modèles pour détecter des comportements anormaux persistants.
* Rechercher des accès non autorisés aux environnements d'entraînement.
* Surveiller les canaux de revente de données ou d'accès liés aux plateformes d'IA.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation de systèmes exposés (contexte de l'incident IA) |
| **T1567** | Exfiltration de données via des services tiers |

---

### Sources

* [https://databreaches.net/2026/11/10/australia-to-introduce-mandatory-reporting-after-openai-hack-to-combat-artificial-intelligence-going-rogue/](https://databreaches.net/2026/11/10/australia-to-introduce-mandatory-reporting-after-openai-hack-to-combat-artificial-intelligence-going-rogue/)


---

<div id="le-modele-mythos-danthropic-super-detecteur-de-bugs-arrive-dans-les-produits-de-cisco-et-ibm"></div>

## Le modèle Mythos d'Anthropic, super détecteur de bugs, arrive dans les produits de Cisco et IBM

### Résumé

Anthropic étend l'accès à son modèle Mythos, spécialisé dans la recherche de bugs, en l'intégrant aux produits de sécurité de Cisco et d'IBM. Cisco a annoncé lors d'un événement à Melbourne que les outils de red teaming de sa suite AI Defense — qui recherche les faiblesses et comportements inappropriés dans les modèles, agents et applications d'IA — pourront appeler Mythos pour tester les environnements clients, sans surcoût pour les licences existantes. IBM a annoncé quelques heures plus tard l'intégration de Mythos dans son outil Concert, qui scanne les applications à la recherche de risques, afin de détecter des faiblesses que les scanners traditionnels manquent, de déterminer celles qui présentent un risque réel et de générer des correctifs soumis à validation des développeurs. Mythos avait initialement été rendu disponible via le programme « Project Glasswing », réservé à des organisations vérifiées, avant d'être élargi à d'autres programmes contrôlés. Anthropic n'a pas souhaité commenter l'existence d'accords similaires avec d'autres tiers.

---

### Analyse opérationnelle

L'arrivée de capacités de découverte de vulnérabilités assistées par IA dans des produits de sécurité grand public modifie l'économie de la recherche de failles : les équipes SOC/AppSec doivent anticiper une réduction du délai entre identification d'une faiblesse et disponibilité d'un exploit, y compris pour des composants applicatifs et des agents IA jusqu'ici peu testés. Concrètement, il faut (1) inventorier les applications et agents IA exposés, (2) intégrer ces scanners dans le pipeline CI/CD avec une politique de priorisation claire, (3) corréler les résultats avec la télémétrie de détection (WAF, IDS, EDR) pour repérer les tentatives d'exploitation des CVE nouvellement révélées, et (4) encadrer strictement l'usage de ces outils, qui constituent eux-mêmes une capacité offensive dual-usage. La génération automatique de correctifs impose également une revue humaine : un patch proposé par un modèle doit passer par les tests de non-régression et l'analyse de sécurité habituelle.

---

### Implications stratégiques

La diffusion de modèles de recherche de bugs de pointe via des éditeurs majeurs (Cisco, IBM) accélère l'industrialisation de la gestion des vulnérabilités, mais abaisse aussi le seuil d'accès à des capacités offensives de haut niveau si les garde-fous ne suivent pas. Pour les directions sécurité, l'enjeu devient moins la détection que la vitesse de remédiation et la gouvernance des modèles dual-usage : politique d'accès, journalisation des requêtes, confidentialité du code soumis, responsabilité contractuelle. Le mouvement dessine une recomposition concurrentielle du marché de la sécurité IA, avec un risque de dépendance à un nombre restreint de fournisseurs de modèles et une pression réglementaire croissante sur la traçabilité et l'usage de l'IA en cybersécurité.

---

### Recommandations

* Cartographier les applications et agents IA exposés avant d'activer des scanners de vulnérabilités assistés par IA.
* Encadrer contractuellement et techniquement l'envoi de code source ou de configurations à un modèle externe.
* Réduire les SLA de remédiation pour les vulnérabilités découvertes par IA et automatiser la priorisation par exploitabilité réelle.
* Exiger une revue humaine systématique des correctifs générés automatiquement avant déploiement.
* Journaliser et limiter les accès aux API de modèles de recherche de vulnérabilités pour prévenir un usage interne malveillant.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les applications, agents et modèles d'IA exposés ou intégrés dans le SI afin de délimiter la surface testable par des outils de red teaming automatisés.
* Intégrer une phase de test de sécurité assistée par IA (type AI Defense / Concert) dans le cycle de développement avant toute mise en production.
* Définir une politique d'usage des modèles dual-usage : qui peut lancer des campagnes de recherche de vulnérabilités, sur quels périmètres, avec quelle traçabilité des requêtes.
* Vérifier la couverture des licences et des clauses contractuelles (responsabilité, confidentialité du code soumis au modèle).

#### Phase 2 — Détection et analyse

* Surveiller les journaux des plateformes de red teaming IA pour détecter des campagnes de scan inhabituelles ou massives.
* Corréler les alertes de vulnérabilités découvertes par les scanners IA avec les tentatives d'exploitation observées en périphérie (WAF, IDS, EDR).
* Mettre en place une détection des requêtes anormales vers les API de modèles externes (volume, heure, identité appelante).

#### Phase 3 — Confinement, éradication et récupération

* Suspendre immédiatement les clés d'API et comptes de service associés en cas d'usage non autorisé du modèle.
* Isoler les applications dont une vulnérabilité critique a été identifiée par le scanner IA avant application du correctif.
* Appliquer un correctif virtuel (WAF/règles proxy) en attendant le patch éditeur.

#### Phase 4 — Activités post-incident

* Mesurer le délai entre découverte automatisée, validation et remédiation pour recalibrer le SLA de patch.
* Mettre à jour la politique de divulgation et de priorisation des vulnérabilités découvertes par IA.
* Documenter les enseignements sur les faux positifs générés par les scanners IA afin d'ajuster les seuils.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs d'accès des signatures d'exploitation correspondant aux CVE récemment découvertes par les scanners IA.
* Traquer les tentatives d'utilisation détournée d'outils de red teaming IA par des comptes internes non habilités.
* Analyser les artefacts d'agents IA compromis (prompts injectés, appels d'outils non prévus).

---

### Sources

* [https://www.theregister.com/ai-and-ml/2026/11/10/anthropics-super-bug-finding-mythos-model-is-going-into-cisco-and-ibm-products/5308616](https://www.theregister.com/ai-and-ml/2026/11/10/anthropics-super-bug-finding-mythos-model-is-going-into-cisco-and-ibm-products/5308616)
* [https://infosec.exchange/@edwardk/117591593275711389](https://infosec.exchange/@edwardk/117591593275711389)


---

<div id="lentreprise-russe-de-cloud-beget-reconstruit-de-zero-apres-une-attaque-par-effaceur-de-donnees"></div>

## L'entreprise russe de cloud Beget reconstruit de zéro après une attaque par effaceur de données

### Résumé

Le fournisseur cloud russe Beget indique qu'une attaque par essuie-données (data wiper) survenue dans la nuit du 1er novembre a permis à un attaquant d'accéder aux systèmes de gestion de l'ensemble de son architecture et d'effacer les données de ses serveurs, l'obligeant à reconstruire son infrastructure cloud à partir de zéro. Plus d'une semaine après, Beget précise que 60 % de l'hébergement mutualisé et 40 % des serveurs dédiés ont été restaurés, que l'ensemble des données cloud (VPS, S3 et Kubernetes) est perdu, et que les sauvegardes de fichiers VPS ne seront disponibles que pour environ la moitié des utilisateurs de VPS.

---

### Analyse opérationnelle

L'élément déterminant est la compromission du plan de gestion de l'architecture, et non des seuls serveurs clients : l'attaquant a obtenu des droits lui permettant d'effacer les données à l'échelle de l'infrastructure, y compris les sauvegardes. Pour un hébergeur, cela se traduit par un impact en cascade sur l'ensemble de la base clients, avec une restauration partielle et une perte définitive de données cloud. Les mesures prioritaires sont la séparation stricte des plans de gestion et de données, l'authentification forte et la restriction réseau des interfaces d'administration, la journalisation immuable des actions de suppression, et des sauvegardes immuables hors ligne avec tests de restauration. La détection doit porter sur les suppressions massives de volumes, buckets et namespaces, ainsi que sur la désactivation des politiques de snapshot.

---

### Implications stratégiques

Cet incident illustre le risque de concentration : la compromission d'un hébergeur se traduit par une perte de données simultanée pour des milliers d'organisations, sans recours possible lorsque les sauvegardes sont elles-mêmes détruites. Dans un contexte de cyberguerre persistante autour des infrastructures russes, les fournisseurs cloud et leurs clients doivent considérer la destruction de données comme un scénario crédible et non comme un cas limite. Les conséquences décisionnelles incluent la diversification multi-fournisseurs, l'exigence contractuelle de garanties de sauvegarde et de restauration, et la réévaluation de la dépendance à un hébergeur unique pour des données critiques.

---

### Recommandations

* Imposer une authentification forte et un accès bastionné aux interfaces d'administration de l'hébergeur.
* Exiger de son fournisseur cloud des sauvegardes immuables, géo-redondées et testées, avec engagement contractuel de restauration.
* Mettre en place une détection dédiée aux suppressions massives et à la modification des politiques de snapshot.
* Conserver une copie hors ligne des données critiques indépendante du fournisseur d'hébergement.
* Préparer et tester un plan de reconstruction complète de l'infrastructure (IaC, runbooks, priorisation des services).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Segmenter le plan de gestion (API, panneau d'administration, hyperviseurs) du plan de données et imposer une authentification forte (MFA matérielle, accès bastion).
* Mettre en place des sauvegardes immuables hors ligne (air-gap, WORM) avec tests de restauration réguliers et copies multi-régions/multi-fournisseurs.
* Documenter les procédures de reconstruction complète de l'infrastructure (IaC, runbooks) et les tester périodiquement.
* Limiter et surveiller les comptes à privilèges élevés disposant de droits de suppression de masse sur le stockage objet et les clusters Kubernetes.

#### Phase 2 — Détection et analyse

* Alerter sur toute suppression ou réinitialisation massive de volumes, buckets S3 ou namespaces Kubernetes en dehors des fenêtres de maintenance.
* Surveiller les connexions inhabituelles aux interfaces d'administration cloud (géolocalisation, horaires, user-agent, échecs d'authentification).
* Détecter la désactivation ou la suppression des politiques de sauvegarde et des snapshots.
* Corréler les journaux d'hyperviseur et de stockage pour identifier les commandes de destruction en rafale.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les sessions et identifiants des comptes administrateurs compromis et faire tourner l'ensemble des secrets.
* Isoler les systèmes de gestion encore opérationnels du réseau pour stopper la propagation du wiper.
* Basculer les services critiques vers une infrastructure de secours et geler les écritures sur les sauvegardes restantes.
* Préserver les images disque et journaux avant toute reconstruction pour l'investigation.

#### Phase 4 — Activités post-incident

* Communiquer aux clients un état précis des données perdues et des capacités de restauration disponibles.
* Reconstruire selon un modèle « zero trust » avec séparation stricte des plans de gestion et de données.
* Revoir la politique de rétention et de sauvegarde (notamment pour les VPS dont les fichiers ne sont récupérables que pour une partie des utilisateurs).
* Conduire un retour d'expérience sur le délai de détection et la capacité de reconstruction, et mettre à jour le plan de continuité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts de wiper (binaires de destruction, tâches planifiées, scripts de suppression récursive) sur les systèmes d'administration.
* Analyser les journaux d'authentification à la recherche d'un accès initial (VPN, API, panneau d'admin) précédant l'attaque.
* Traquer les mouvements latéraux entre plan de gestion et plan de données via les comptes de service.
* Vérifier l'absence de persistance résiduelle (clés API, comptes fantômes, webhooks) avant remise en production.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1485** | Data Destruction — effacement des données serveurs et des systèmes de gestion |
| **T1561** | Disk Wipe — attaque par essuie-données (data wiper) |
| **T1078** | Valid Accounts — accès aux systèmes de management de l'architecture cloud |
| **T1490** | Inhibit System Recovery — perte des sauvegardes et des données cloud (VPS, S3, Kubernetes) |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/russian-cloud-firm-beget-rebuilds-from-scratch-after-data-wiper-attack/](https://www.bleepingcomputer.com/news/security/russian-cloud-firm-beget-rebuilds-from-scratch-after-data-wiper-attack/)
* [https://infosec.exchange/@edwardk/117591592388558378](https://infosec.exchange/@edwardk/117591592388558378)


---

<div id="remus-stealer-commercialise-un-acces-persistant-a-gmail-hudson-rock-enquete"></div>

## Remus Stealer commercialise un accès persistant à Gmail – Hudson Rock enquête

### Résumé

Un article publié par InfoStealers rapporte que Hudson Rock a enquêté sur le stealer dénommé Remus, qui met en avant la capacité de fournir un accès persistant aux comptes Gmail. Le contenu détaillé de l'analyse n'est pas exploitable dans la source collectée ; seuls le sujet et l'objet de l'enquête sont confirmés.

---

### Analyse opérationnelle

La promesse d'un « accès persistant » à Gmail renvoie aux modes opératoires classiques des infostealers : collecte des identifiants et des cookies de session des navigateurs, récupération de jetons OAuth ou de mots de passe d'application, puis revente d'un accès déjà authentifié contournant la MFA. Pour les équipes SOC, la détection doit porter sur la réutilisation de cookies de session (connexions sans nouvelle authentification, changement d'empreinte appareil), la création de règles de transfert automatique, l'apparition de consentements OAuth inconnus et l'usage de mots de passe d'application. La réponse impose la révocation globale des sessions et jetons, la réinitialisation des secrets et l'isolement du poste infecté.

---

### Implications stratégiques

La spécialisation des stealers sur la persistance dans les messageries grand public transforme un vol d'identifiants en accès durable à l'écosystème SaaS de l'organisation : rebond vers d'autres services liés au compte Google, fraude au virement, compromission de messagerie professionnelle. Cela alimente le marché des courtiers d'accès initiaux et impose de traiter la messagerie personnelle des collaborateurs comme une dépendance de la surface d'attaque d'entreprise, avec les arbitrages qui en découlent en matière de politique d'usage, de MFA résistante au phishing et de surveillance des consentements OAuth.

---

### Recommandations

* Généraliser les clés de sécurité FIDO2 pour les comptes de messagerie critiques afin de neutraliser la réutilisation de cookies et de jetons.
* Auditer et restreindre les applications OAuth tierces autorisées sur les comptes Google de l'organisation.
* Détecter la création de règles de transfert ou de masquage dans les boîtes mail et alerter en temps réel.
* Révoquer systématiquement sessions et jetons lors d'une suspicion de compromission de poste.
* Surveiller les bases de fuites d'identifiants pour identifier les comptes déjà exposés et déclencher des réinitialisations préventives.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les comptes Google Workspace / Gmail critiques et imposer l'authentification forte résistante au phishing (clés FIDO2).
* Restreindre les applications OAuth tierces autorisées et mettre en place une revue périodique des consentements.
* Activer la journalisation détaillée des connexions et des règles de boîte aux lettres, avec export vers le SIEM.
* Sensibiliser les utilisateurs aux leurres de distribution d'infostealers (faux installateurs, cracks, publicités malveillantes).

#### Phase 2 — Détection et analyse

* Détecter les connexions aux comptes de messagerie depuis des localisations ou appareils incohérents avec l'usage habituel.
* Alerter sur la création de règles de transfert ou de masquage automatique de messages.
* Surveiller l'apparition de nouveaux consentements OAuth et l'usage de mots de passe d'application.
* Rechercher sur les postes les artefacts d'infostealers (accès aux bases de navigateurs, archives de profils, exfiltration HTTP sortante).

#### Phase 3 — Confinement, éradication et récupération

* Révoquer toutes les sessions actives et jetons OAuth des comptes compromis.
* Réinitialiser les mots de passe et invalider les mots de passe d'application.
* Supprimer les règles de boîte aux lettres et délégations créées par l'attaquant.
* Isoler le poste infecté et lancer une analyse complète avant remise en réseau.

#### Phase 4 — Activités post-incident

* Notifier les utilisateurs et, le cas échéant, les tiers impactés par des messages frauduleux émis depuis les comptes compromis.
* Vérifier l'absence de persistance (applications OAuth, appareils de confiance, numéros de récupération modifiés).
* Renforcer la politique de mot de passe et généraliser les clés de sécurité matérielles.
* Mettre à jour la détection à partir des artefacts du stealer identifié.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux d'authentification les accès aux comptes de messagerie depuis des adresses IP ou ASN inhabituels.
* Traquer les requêtes sortantes vers des endpoints d'exfiltration connus ou suspects depuis les postes utilisateurs.
* Analyser les journaux de la console d'administration pour identifier des modifications de paramètres de sécurité de comptes.
* Corréler avec les bases de fuites d'identifiants pour identifier des comptes déjà exposés.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1555.003** | Credentials from Password Stores — Credentials from Web Browsers |
| **T1539** | Steal Web Session Cookie — réutilisation de sessions authentifiées |
| **T1550.001** | Use Alternate Authentication Material — Application Access Token |
| **T1566** | Phishing — vecteur probable de distribution du stealer |

---

### Sources

* [https://www.infostealers.com/article/remus-stealer-markets-persistent-gmail-access-hudson-rock-investigates/](https://www.infostealers.com/article/remus-stealer-markets-persistent-gmail-access-hudson-rock-investigates/)
* [https://infosec.exchange/@edwardk/117591584825548837](https://infosec.exchange/@edwardk/117591584825548837)
