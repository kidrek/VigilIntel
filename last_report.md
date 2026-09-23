# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [La vérité sur GET et les normes HTTP, (mardi 22 septembre)](#la-verite-sur-get-et-les-normes-http-mardi-22-septembre)
  * [Analyse de LausivLoader, ou comment transmettre des données entre les étapes d'un malware, (jeudi 17 septembre)](#analyse-de-lausivloader-ou-comment-transmettre-des-donnees-entre-les-etapes-dun-malware-jeudi-17-septembre)
  * [Campagnes de phishing par code d'appareil : CSuite cible les organisations américaines et de l'UE et analyse des causes profondes d'EvilTokens](#campagnes-de-phishing-par-code-dappareil-csuite-cible-les-organisations-americaines-et-de-lue-et-analyse-des-causes-profondes-deviltokens)
  * [Les identités à risque continuent de hanter les infrastructures cloud](#les-identites-a-risque-continuent-de-hanter-les-infrastructures-cloud)
  * [Le Quorum Fermé : à l'intérieur du premier implant C2 IA autonome signalé](#le-quorum-ferme-a-linterieur-du-premier-implant-c2-ia-autonome-signale)
  * [Phishing par QR code rendu en texte dans le framework PhishU](#phishing-par-qr-code-rendu-en-texte-dans-le-framework-phishu)
  * [Scanner malveillant 35.195.46.200, hébergé dans Google Cloud (ASN 396982)](#scanner-malveillant-3519546200-heberge-dans-google-cloud-asn-396982)
  * [ShinyHunters intensifie le conflit avec le FBI ; affirme avoir saisi le site des candidats et acquis des données](#shinyhunters-intensifie-le-conflit-avec-le-fbi-affirme-avoir-saisi-le-site-des-candidats-et-acquis-des-donnees)
  * [Des hackers chinois exploitent plusieurs technologies pour voler des données gouvernementales](#des-hackers-chinois-exploitent-plusieurs-technologies-pour-voler-des-donnees-gouvernementales)
  * [Don-themes scores D for trust: 100% of its 7 CVEs unpatched, avg CVSS 8.16 and rising. WordPress themes carrying critical RCE and SQLi flaws are a favorite entry point. Check your stack.](#don-themes-scores-d-for-trust-100-of-its-7-cves-unpatched-avg-cvss-816-and-rising-wordpress-themes-carrying-critical-rce-and-sqli-flaws-are-a-favorite-entry-point-check-your-stack)
  * [124.220.78.244 est signalé comme un scanner (confiance 62, suivi par 3 flux). Il a été lié à l'exploitation de CVE, donc vérifiez vos journaux pour des correspondances.](#12422078244-est-signale-comme-un-scanner-confiance-62-suivi-par-3-flux-il-a-ete-lie-a-lexploitation-de-cve-donc-verifiez-vos-journaux-pour-des-correspondances)
  * [Un responsable cyber israélien accusé d'avoir accédé à distance à des caméras, volé des mots de passe et infiltré 26 entreprises](#un-responsable-cyber-israelien-accuse-davoir-accede-a-distance-a-des-cameras-vole-des-mots-de-passe-et-infiltre-26-entreprises)
  * [Les écoles publiques de Spokane mettent certains systèmes hors ligne après un « incident de sécurité réseau »](#les-ecoles-publiques-de-spokane-mettent-certains-systemes-hors-ligne-apres-un-incident-de-securite-reseau)
  * [Un membre précoce de Scattered Spider plaide coupable pour une série de cybercrimes](#un-membre-precoce-de-scattered-spider-plaide-coupable-pour-une-serie-de-cybercrimes)
  * [Prenez une chaise. C'est mardi soir, et vous avez probablement passé votre journée à fixer un tableau de bord affichant tous les voyants au vert alors que votre instinct vous dit que quelque chose ne va pas.https://theperimetersite.com/report/292#databreach #infosec](#prenez-une-chaise-cest-mardi-soir-et-vous-avez-probablement-passe-votre-journee-a-fixer-un-tableau-de-bord-affichant-tous-les-voyants-au-vert-alors-que-votre-instinct-vous-dit-que-quelque-chose-ne-va-pashttpstheperimetersitecomreport292databreach-infosec)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La journée est dominée par les vulnérabilités avec 42 publications, signalant une pression opérationnelle forte sur la gestion des correctifs et l’exposition externe. Les fuites de données restent élevées à 15 cas, ce qui suggère une activité continue d’exploitation ou de divulgation affectant potentiellement plusieurs secteurs. Le volet réglementaire (7) et géopolitique (5) demeure modéré mais structurant, avec des implications possibles sur la conformité, la notification et les risques pays. L’absence de signalement sur les threat actors (0) ne signifie pas une accalmie : elle peut refléter un décalage de collecte ou une attribution en cours. La priorité stratégique est donc de corréler les vulnérabilités critiques avec les fuites de données pour identifier les chemins d’attaque les plus probables. Il convient de renforcer la veille sur les correctifs urgents, les indicateurs de compromission et les obligations réglementaires associées. En parallèle, la composante géopolitique doit être surveillée pour anticiper les campagnes ciblées ou les effets de bord sur la chaîne d’approvisionnement. En synthèse, le risque quotidien est davantage technique et expositionnel que lié à des acteurs nommés, ce qui impose une réponse rapide en patch management et en détection.

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
| **Mondial** | Renseignement et défense | IA et souveraineté : le renseignement à l'ère des agents autonomes | L'article de Recorded Future défend la thèse selon laquelle l'IA a rendu le raisonnement ubiquitaire et bon marché, déplaçant la valeur stratégique vers ceux qui raisonnent le plus efficacement et décident le plus vite. Le parallèle historique est explicite : là où le renseignement recrutait et pilotait des agents humains (un officier expérimenté ne gérait qu'une poignée de sources), les agents IA deviennent désormais les principaux consommateurs d'intelligence. Le ratio humain/agent va s'inverser, ce qui réduit le coût du « agent running » mais accroît la dépendance à la qualité et à la fraîcheur du renseignement. L'auteur mobilise des précédents historiques (crise des missiles de Cuba, débarquement de Normandie) pour souligner que l'avantage décisif provient de la fusion multi-sources (GEOINT, HUMINT, SIGINT, météo). Il en tire une conclusion commerciale et géopolitique : la souveraineté — le contrôle de son destin — appartiendra aux États et organisations disposant d'une couche de renseignement fiable alimentant leurs systèmes agentiques. Le texte est un plaidoyer pour les plateformes de threat intelligence capables de suivre les TTP en temps réel et de s'articuler aux capacités IA. Il cite Bill Burns (« la bonne politique repose sur du bon renseignement bien utilisé »). Aucune menace opérationnelle directe, mais un cadrage doctrinal sur la compétition IA entre puissances. | [https://www.recordedfuture.com/blog/agent-running-ai](https://www.recordedfuture.com/blog/agent-running-ai) |
| **Corée du Nord, Ukraine, Russie, Corée du Sud, Europe** | Diplomatie, think tanks, ONG, défense | Opération Conflict Compass : Konni (RPDC) espionne le dossier ukrainien via des LNK malveillants | Le STRU de SOCRadar documente l'opération Conflict Compass, campagne attribuée à Konni (TA406 / Opal Sleet), groupe lié à la RPDC opérant sous le General Reconnaissance and Information Bureau (GRIB) et considéré comme un sous-groupe de l'ombrelle Kimsuky. Lancée début août 2026 et détectée via des échantillons publiés début septembre, la campagne vise des individus et entités liés à l'Ukraine afin de renseigner Pyongyang sur la trajectoire de l'invasion russe et les perspectives à moyen terme du conflit. Le vecteur d'accès initial est le spear-phishing par courriel avec archives ZIP contenant des fichiers LNK déguisés en PDF. Les leurres exploitent trois thématiques : la hausse des prix alimentaires mondiaux liée à la situation du détroit d'Ormuz, les documents de négociation de paix Russie-Ukraine, et des CV de chercheurs en sciences sociales — ce qui suggère un ciblage d'entités diplomatiques, de think tanks et d'ONG. L'exécution déclenche un VBScript qui établit une persistance via tâche planifiée, lançant un script PowerShell toutes les minutes. Le payload, baptisé VelvetCake, est un downloader modulaire sans capacité post-exploitation fixe : il récupère et exécute des modules PowerShell côté serveur, permettant aux opérateurs de modifier les fonctionnalités sans redéployer le cœur du malware. L'infrastructure repose sur des sites sud-coréens et ukrainiens pour l'hébergement des leurres, GitHub pour le staging des scripts, et Medianewsonline (service de sous-domaines gratuits) pour le C2. L'attribution s'appuie sur le ciblage ukrainien, les signatures de code VelvetCake, l'infrastructure partagée et l'alignement du fuseau horaire opérationnel. Enjeu géopolitique : la RPDC monétise et renseigne son programme nucléaire via le cyber, tout en se positionnant comme observateur intéressé du conflit ukrainien. | [https://socradar.io/blog/operation-conflict-compass-konni-ukraine-lnk-lure/](https://socradar.io/blog/operation-conflict-compass-konni-ukraine-lnk-lure/) |
| **États-Unis, Porto Rico** | Cybersécurité, politique, médias | Revue hebdomadaire : guerre entre groupes ransomware, désinformation électorale et régulation à Porto Rico | Cette édition du bulletin Threat Model agrège plusieurs signaux à dimension géopolitique et cyber. Le fait marquant est la prise de contrôle du gang ransomware Cl0p par ShinyHunters, assortie de menaces de « public shaming » — signe de recomposition et de rivalités au sein de l'écosystème cybercriminel, avec un risque accru de fuites et de chantage pour les victimes. Sur le plan politique, deux points retiennent l'attention : Washington refuse à Porto Rico la capacité de réguler la désinformation en situation d'urgence, ce qui pose la question de la souveraineté numérique d'un territoire non incorporé et de la protection de ses populations lors de crises ; et le bulletin évoque les scénarios de contestation ou de « vol » des élections de mi-mandat américaines, alimentant les narratives de défiance institutionnelle. Sont également mentionnés un cas d'erreur d'identité liée à l'IA aux conséquences graves, la faiblesse de la sécurité des dispositifs Flock (surveillance), et un projet artistique sur l'ère « Far West » d'Internet. L'ensemble illustre la convergence entre criminalité cyber, ingérences informationnelles et enjeux de gouvernance. | [https://www.patreon.com/violetblue/posts/cybersecurity-22-170230450](https://www.patreon.com/violetblue/posts/cybersecurity-22-170230450) |
| **France, Vatican, Europe** | Diplomatie, affaires religieuses, société | Visite du pape en France : quels messages géopolitiques et sociétaux ? | Dans le cadre des « Mardis de l'IRIS », Pascal Boniface (directeur de l'IRIS) s'entretient avec François Mabille, chercheur associé et directeur de l'Observatoire géopolitique du religieux, à propos de la visite du pape en France prévue du 25 au 28 septembre. L'échange porte sur les enjeux de cette visite, à la croisée des équilibres internationaux, de la mondialisation et des débats de société français. Le religieux est ici analysé comme facteur structurant des relations internationales et des équilibres internes, dans une séquence où le Vatican cherche à peser sur les questions de paix, de migration, d'écologie et de cohésion sociale. La portée du message papal pour la France dépasse le cadre confessionnel : il s'inscrit dans une diplomatie pontificale active et dans un contexte européen de recomposition politique. | [https://www.iris-france.org/quel-message-du-pape-pour-la-france-les-mardis-de-liris/](https://www.iris-france.org/quel-message-du-pape-pour-la-france-les-mardis-de-liris/) |
| **Tchéquie, Union européenne, OTAN** | Défense et sécurité, industrie, administration publique | Intégration du processus capacitaire européen dans les administrations nationales : le cas tchèque | Martin Chovančík (Université Masaryk) évalue comment la Tchéquie a intégré les instruments capacitaires de l'UE dans sa politique de défense nationale. Constat central : un fort alignement de fond mais une internalisation plus faible. Les plans tchèques recoupent largement le Capability Development Plan, mais cela s'explique surtout par le remplacement d'équipements soviétiques, le réapprovisionnement des stocks donnés à l'Ukraine et la correction de lacunes capacitaire larges — et non par une détermination européenne de l'ordre des acquisitions. La séquence d'acquisition reste ancrée dans les besoins nationaux, l'héritage de structure de force, les intérêts industriels domestiques et les cibles OTAN. PESCO a produit de l'accès, des progrès d'interopérabilité et un rôle de leadership tchèque clair, mais n'a pas systématiquement converti la participation en achats ou en leadership industriel. L'intégration est la plus forte là où les instruments européens apportent un financement tangible : le Fonds européen de défense, ASAP et SAFE ont commencé à modifier les incitations et les pratiques administratives. Même là, des effectifs très limités, une entrée tardive dans les consortiums et une structure industrielle averse au risque limitent les résultats. Conclusion : l'intégration tchèque au processus capacitaire européen est sélective et essentiellement en aval. Enjeu géopolitique : la capacité de l'UE à transformer ses instruments en effets capacitaires réels face à la menace russe et à la dépendance aux garanties OTAN. | [https://www.iris-france.org/integration-of-the-european-capability-process-in-member-states-administration-the-czech-case/](https://www.iris-france.org/integration-of-the-european-capability-process-in-member-states-administration-the-czech-case/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| IMY – sanction administrative SEK 1,8 M (art. 32(1) RGPD) – affaire Miljödata | IMY (Integritetsskyddsmyndigheten – autorité suédoise de protection des données) | 2026-09-22 | Suède / Union européenne (RGPD) | IMY – sanction administrative SEK 1,8 M (art. 32(1) RGPD) – affaire Miljödata | L'IMY a sanctionné Miljödata, fournisseur de logiciels RH et d'environnement de travail utilisés par environ 80 % des systèmes municipaux suédois, à hauteur de 1,8 million de SEK (environ 183 000 USD) pour violation de l'article 32(1) du RGPD. L'attaque du 25 août 2025 a perturbé les services informatiques de plus de 200 régions et exposé les données sensibles de 2,2 millions de personnes : numéros d'identité personnels, coordonnées, arrêts maladie, données de réadaptation et signalements d'incidents scolaires impliquant des mineurs. Les données ont été publiées sur le dark web sous l'appellation « Datacarry » après une demande de rançon de 1,5 BTC (environ 168 000 USD) restée sans effet dissuasif. Le point juridiquement structurant est que la décision de l'IMY ne se fonde pas sur l'ampleur médiatique de la brèche mais sur deux manquements techniques et organisationnels identifiés comme contrôlables : l'absence de vérifications suffisantes lors de l'installation de nouveaux logiciels et l'absence de surveillance automatisée en temps réel permettant de détecter les intrusions et activités suspectes. L'IMY a par ailleurs ouvert des enquêtes distinctes visant deux municipalités et une région, ce qui laisse présager des sanctions additionnelles et une extension de la responsabilité aux sous-traitants et aux entités publiques clientes. Ce dossier illustre la tendance réglementaire européenne à cibler les mesures de sécurité de base (validation logicielle, supervision continue) plutôt que le seul volume de données compromises, et à considérer la chaîne de sous-traitance municipale comme un périmètre de risque réglementaire à part entière. | [https://osintsights.com/sweden-fines-miljodata-183000-for-gdpr-breach-over-inadequate-security?utm_source=mastodon&utm_medium=social](https://osintsights.com/sweden-fines-miljodata-183000-for-gdpr-breach-over-inadequate-security?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117316901960435812](https://mastodon.social/@Analyst207/117316901960435812) |
| Parquet de Paris – enquêtes ouvertes pour captation d'images sans consentement (lunettes connectées) | Parquet de Paris (autorité judiciaire française) | 2026-09-22 | France | Parquet de Paris – enquêtes ouvertes pour captation d'images sans consentement (lunettes connectées) | Le parquet de Paris a ouvert plusieurs enquêtes à la suite de plaintes déposées par des femmes filmées sans leur consentement dans l'espace public au moyen de lunettes connectées. Le dossier s'inscrit dans le contentieux émergent des dispositifs portables à captation discrète, où la frontière entre usage récréatif, captation de masse et atteinte à la vie privée devient difficile à tracer pour les enquêteurs comme pour les utilisateurs. Sur le plan juridique, les qualifications mobilisables relèvent de la captation et de la diffusion d'images de personnes sans consentement, de l'atteinte à l'intimité de la vie privée et, le cas échéant, du harcèlement ou de la diffusion non consentie à caractère sexuel. Le fait que plusieurs enquêtes distinctes soient ouvertes suggère un faisceau de plaintes convergentes plutôt qu'un incident isolé, ce qui peut préfigurer une réponse pénale structurée et une attention accrue des autorités sur les usages des lunettes à caméra intégrée. Le dossier présente également une dimension réglementaire européenne, ces dispositifs relevant du cadre applicable aux produits connectés et au traitement de données personnelles, avec des obligations d'information et de minimisation qui sont rarement respectées en pratique lors d'une captation en rue. | [https://www.lemonde.fr/pixels/article/2026/09/22/lunettes-connectees-le-parquet-de-paris-ouvre-plusieurs-enquetes-apres-des-plaintes-de-femmes-filmees-sans-leur-consentement_6780288_4408996.html](https://www.lemonde.fr/pixels/article/2026/09/22/lunettes-connectees-le-parquet-de-paris-ouvre-plusieurs-enquetes-apres-des-plaintes-de-femmes-filmees-sans-leur-consentement_6780288_4408996.html) |
| LAPSUS$ « Chapter II » – détournement d'API Elsevier / GSDD (lapsus[.]ar[.]io, lapsus[.]bz) | Elsevier (victime, communication officielle) ; LAPSUS$ (revendication) ; aucune autorité réglementaire saisie à ce stade | 2026-09-22 | International (infrastructure Elsevier / Gold Standard Drug Database, utilisateurs États-Unis et international) | LAPSUS$ « Chapter II » – détournement d'API Elsevier / GSDD (lapsus[.]ar[.]io, lapsus[.]bz) | Des utilisateurs et des systèmes tentant de se connecter aux plateformes Elsevier Evolve, Sherpath et ClinicalPharmacology ont été redirigés vers des pages d'extorsion attribuées à LAPSUS$, pointant notamment vers lapsus[.]ar[.]io et lapsus[.]bz. Au-delà des portails étudiants, l'impact réel touche l'infrastructure d'API de santé : les points d'authentification de production d'Elsevier et des services Gold Standard Drug Database, dont api[.]gsdd[.]net/auth/AccessToken, ont renvoyé des redirections vers des pages contrôlées par l'attaquant au lieu de jetons d'accès valides. Cette manipulation de la chaîne d'authentification est le point le plus préoccupant : elle peut permettre l'interception de jetons, la compromission de sessions applicatives et l'injection de réponses falsifiées dans des flux cliniques. Elsevier conteste l'ampleur, qualifiant l'événement de redirection temporaire, étroitement circonscrite et de courte durée, sans indication de compromission des plateformes cœur, des données clients, des contenus de recherche ou des systèmes opérationnels. LAPSUS$ revendique un retour sous l'étiquette « Chapter II » après une retraite annoncée en juillet, avec un message signé PGP ciblant explicitement le FBI et l'appareil fédéral américain, et annonçant la poursuite des violations, extorsions et générations de revenus. Le décalage entre la communication de la victime et l'analyse de tiers illustre la difficulté d'établir le périmètre réel d'une compromission de chaîne d'authentification, et le risque réglementaire associé (notification de violation, obligations sectorielles santé type HIPAA, contrats clients). | [https://databreaches.net/2026/09/22/elsevier-evolve-clinicalpharmacology-and-gsdd-apis-hijacked-lapsus-redirect-campaign/](https://databreaches.net/2026/09/22/elsevier-evolve-clinicalpharmacology-and-gsdd-apis-hijacked-lapsus-redirect-campaign/) |
| Proofpoint Protect 2026 – annonces Agentic Collaboration Security et Agentic Data & AI Security | Proofpoint, Inc. (éditeur de cybersécurité, annonce produit) | 2026-09-22 | International (annonces commerciales, Proofpoint Protect 2026, San Diego) | Proofpoint Protect 2026 – annonces Agentic Collaboration Security et Agentic Data & AI Security | Proofpoint a annoncé deux systèmes agentiques lors de Proofpoint Protect 2026. Le premier, Agentic Collaboration Security, repose sur le Knowledge Graph de Proofpoint et sur le nouveau modèle de détection par intention Nexus : il raisonne sur le contexte d'une interaction (relations d'affaires, fournisseurs compromis, habitudes de communication, accès aux données, risque utilisateur) pour distinguer une intention malveillante d'une activité légitime, avec des décisions majoritairement rendues en moins d'une demi-seconde et une analyse approfondie pour les cas ambigus. Le second, Agentic Data and AI Security, vise à unifier la sécurité des données et celle de l'IA dans un même graphe, avec trois agents autonomes (détection, investigation, remédiation) et des politiques métier sémantiques appliquées au runtime. L'argument réglementaire et de gouvernance est explicite : les agents IA accèdent, transforment et exécutent des opérations sur des données sensibles à une échelle qu'aucune revue manuelle ne peut couvrir, et la gouvernance de l'IA dépasse désormais la seule prévention de fuite de données pour englober des risques financiers, opérationnels, de conformité et de sécurité. Proofpoint cite son rapport 2026 AI and Human Risk Landscape : 87 % des organisations ont dépassé le stade du pilote pour les assistants IA, mais 52 % ne sont pas confiantes dans la capacité de leurs contrôles à détecter une compromission. Ces annonces relèvent de la communication produit et non d'une obligation réglementaire, mais elles s'inscrivent dans un contexte où les exigences de gouvernance de l'IA et de conformité (traçabilité, contrôle d'accès, minimisation) pèsent de plus en plus sur les déploiements d'agents autonomes. | [https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-stops-attacks-traditional-defenses-miss-ai-era](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-stops-attacks-traditional-defenses-miss-ai-era)<br>[https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-breaks-down-divide-between-data-security-and-ai-security](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-breaks-down-divide-between-data-security-and-ai-security) |
| OpenSSF – What's in the SOSS? Podcast #73 (CRA, vélocité IA, dette de dépendances) | OpenSSF (Open Source Security Foundation) – contenu éditorial, pas d'autorité de régulation | 2026-09-22 | Union européenne (Cyber Resilience Act) et écosystème open source international | OpenSSF – What's in the SOSS? Podcast #73 (CRA, vélocité IA, dette de dépendances) | L'épisode 73 du podcast What's in the SOSS de l'OpenSSF aborde la convergence entre la vélocité de développement induite par l'IA, la mise en conformité au Cyber Resilience Act (CRA) européen et la dette de dépendances dans les chaînes logicielles open source. Le format est éditorial et le contenu textuel de la source est extrêmement limité, ce qui restreint l'analyse à la thématique annoncée. Le sujet est néanmoins structurant : le CRA impose aux fabricants de produits comportant des éléments numériques des obligations de sécurité tout au long du cycle de vie, y compris pour les composants tiers et open source intégrés, ce qui entre en tension directe avec l'accélération des cycles de développement assistés par IA et avec l'opacité des chaînes de dépendances. La notion de « dette de dépendances » désigne l'accumulation de composants non maintenus, non inventoriés ou non patchés, qui devient un risque de conformité autant qu'un risque technique. Les mainteneurs open source se retrouvent de fait en position de fournisseurs critiques sans les moyens correspondants, ce qui pose la question du partage de responsabilité entre éditeurs, intégrateurs et communautés. | [https://openssf.org/podcast/2026/09/22/whats-in-the-soss-podcast-73-s3e25-securing-the-source-navigating-ai-velocity-cra-compliance-and-dependency-debt-with-abby-kearns/](https://openssf.org/podcast/2026/09/22/whats-in-the-soss-podcast-73-s3e25-securing-the-source-navigating-ai-velocity-cra-compliance-and-dependency-debt-with-abby-kearns/) |
| DROS-VEP Lite – RFC-010, gouvernance déterministe de l'exécution des agents (VEP v0.2.0) | Projet de recherche ouvert DROS-VEP (RFC-010) – infrastructure d'évaluation, pas d'autorité réglementaire | 2026-09-22 | International (recherche ouverte, sans rattachement juridique national) | DROS-VEP Lite – RFC-010, gouvernance déterministe de l'exécution des agents (VEP v0.2.0) | Le projet DROS-VEP Lite propose un environnement d'évaluation ouvert et indépendant de toute implémentation pour déterminer si les contrôles de sécurité d'un agent IA restent efficaces après compromission, en particulier à la frontière entre l'autorisation accordée à l'agent et l'exécution système réelle. La thèse centrale est qu'un bac à sable (sandbox) n'équivaut pas à une gouvernance de l'exécution : les défenses classiques (inspection de prompts, garde-fous, observation post-hoc des journaux) échouent silencieusement lorsque la couche cognitive de l'agent est détournée par injection de prompt directe ou indirecte, détournement de contexte ou hallucination d'outil. DROS se positionne comme un substrat de gouvernance d'exécution déterministe, établissant une frontière d'application explicite et in-band entre la décision d'agir de l'agent et l'action système qui suit, de sorte que même un agent entièrement détourné conserve une autorité bornée sur les appels système, les API de fichiers, les sockets réseau et les outils d'entreprise. La doctrine revendiquée est volontairement minimaliste (« étroit en responsabilité, profond en application ») : l'identité et les credentials restent à l'IAM d'entreprise, l'orchestration métier aux frameworks d'agents, l'agrégation de journaux au SIEM. Le statut actuel est gelé sur les jalons M1 à M3 (contrat d'exécution canonique, évaluation empirique sur cinq substrats, limites de couverture sémantique négative), avec un canal ouvert de falsification adversariale invitant les chercheurs à soumettre des contre-exemples. Le projet ne produit pas de score de sécurité unique mais mesure quelles propriétés post-compromission chaque substrat peut réellement appliquer, lesquelles il ne peut pas exprimer nativement et lesquelles ne peuvent être établies que par assurance formelle. | [https://github.com/Top-Celestial-Company-Ltd/DROS-VEP-lite](https://github.com/Top-Celestial-Company-Ltd/DROS-VEP-lite)<br>[https://www.reddit.com/r/redteamsec/comments/1wn7ves/why_the_agent_has_a_sandbox_is_not_the_same_as/](https://www.reddit.com/r/redteamsec/comments/1wn7ves/why_the_agent_has_a_sandbox_is_not_the_same_as/) |
| Global Cyber Alliance – Brian Cute on collective cyber action | Global Cyber Alliance (organisation à but non lucratif) – contenu éditorial et de plaidoyer | 2026-09-22 | International (gouvernance et coopération cyber, sans portée normative directe) | Global Cyber Alliance – Brian Cute on collective cyber action | L'article de la Global Cyber Alliance, signé par Brian Cute, traite de la forme concrète que prend l'action cyber collective. Le texte exploitable est très limité (le contenu utile se réduit à l'introduction), mais la thèse annoncée est claire : l'activité de cybersécurité est abondante et provient d'acteurs hétérogènes — gouvernements, entreprises technologiques, société civile, philanthropies, organisations internationales et chercheurs — et la question posée n'est pas celle du volume d'initiatives mais celle de leur coordination effective et de leur efficacité mesurable. Ce type de contribution relève du plaidoyer et de la définition de cadres de coopération plutôt que de la réglementation contraignante, mais il alimente directement les débats sur la gouvernance cyber, la mutualisation des moyens et la répartition des responsabilités entre secteur public et privé. En l'absence de contenu détaillé, aucune conclusion opérationnelle ne peut être tirée au-delà de la thématique. | [https://globalcyberalliance.org/brian-cute-on-what-collective-cyber-action-actually-looks-like/](https://globalcyberalliance.org/brian-cute-on-what-collective-cyber-action-actually-looks-like/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Services juridiques (cabinets d'avocats)** | Multiple law firms (e.g., Clark Hill, Cozen O'Connor, Hogan Lovells, Katten Muchin Rosenman, Greenberg Traurig, Holland & Knight, Troutman Pepper Locke, Reminger, Riker Danzig, Rutan & Tucker, Floyd Skeren Manukian Langevin, Ropers Majeski, Farella Braun + Martel, Sandberg Phoenix, Porter Wright, Marshall Dennehey, Barclay Damon, Fox Rothschild, Mayer Brown, Moses & Singer, Fagen Friedman & Fulfrost, Cox Castle & Nicholson, Goulston & Storrs) | Données non spécifiées, probablement des documents juridiques, des informations clients, des emails, etc. | Inconnu | [https://www.ransomlook.io//group/leakeddata](https://www.ransomlook.io//group/leakeddata)<br>`hxxps://www[.]ransomlook[.]io//group/leakeddata` |
| **Réseaux sociaux / Communication** | Discord (third-party vendor breach affecting users) | Photos de pièces d'identité gouvernementales (permis de conduire, cartes d'identité) d'environ 70 000 utilisateurs. | 70000 | [https://discord.com/blog/safer-for-teens-same-discord-for-adults](https://discord.com/blog/safer-for-teens-same-discord-for-adults)<br>[https://infosec.exchange/@technotenshi/117316746012934298](https://infosec.exchange/@technotenshi/117316746012934298)<br>`hxxps://discord[.]com/blog/safer-for-teens-same-discord-for-adults` |
| **Vérification d'identité / Services** | IDScan (users' driver's license and government ID information) | Permis de conduire, informations d'identité gouvernementale. | Inconnu | [https://infosec.exchange/@TycoonTom/117316533519254925](https://infosec.exchange/@TycoonTom/117316533519254925)<br>`hxxps://infosec[.]exchange/@TycoonTom/117316533519254925` |
| **Santé (hôpitaux, cliniques)** | Grupo Hospifar S.R.L. | Données non spécifiées, probablement des données patients, des informations médicales, etc. | Inconnu | [https://www.ransomlook.io//group/titan](https://www.ransomlook.io//group/titan)<br>`hxxps://www[.]ransomlook[.]io//group/titan` |
| **Cybersécurité** | CrowdSec | Code source privé (170 dépôts GitHub), y compris des secrets potentiels. | 170 dépôts GitHub privés | [https://www.darkreading.com/cyberattacks-data-breaches/shai-hulud-attack-cyber-firm-crowdsec-github-data](https://www.darkreading.com/cyberattacks-data-breaches/shai-hulud-attack-cyber-firm-crowdsec-github-data)<br>[https://infosec.exchange/@cloud/117316238243150588](https://infosec.exchange/@cloud/117316238243150588) |
| **Cryptomonnaie / Finance** | Haruko | Clés API en lecture seule, données de portefeuille, informations sur les clients. | 15 clients institutionnels | [https://cyber.netsecops.io/articles/crypto-firm-haruko-breached-15-clients-affected/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/crypto-firm-haruko-breached-15-clients-affected/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117315993954565976](https://mastodon.social/@netsecio/117315993954565976) |
| **E-commerce** | BigCommerce | Noms, adresses e-mail, numéros de téléphone, adresses de livraison. | Nombre non divulgué, mais plusieurs centaines de boutiques potentiellement affectées | [https://cyber.netsecops.io/articles/bigcommerce-supply-chain-breach-via-compromised-ribon-app/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/bigcommerce-supply-chain-breach-via-compromised-ribon-app/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117315992773415176](https://mastodon.social/@netsecio/117315992773415176) |
| **Marketing B2B** | LimeLeads | Adresses e-mail, employeurs, localisations géographiques, titres de poste, numéros de téléphone. | 17 838 396 comptes | [https://haveibeenpwned.com/Breach/LimeLeads](https://haveibeenpwned.com/Breach/LimeLeads) |
| **Technologie / Service de capture d'écran** | Gyazo (Helpfeel) | Identifiants de compte, adresses e-mail, captures d'écran potentiellement sensibles. | 23600000 | [https://tech-insider.org/gyazo-data-breach-23-6-million-users-2026](https://tech-insider.org/gyazo-data-breach-23-6-million-users-2026)<br>[https://infosec.exchange/@security_crawler_carl/117317305470834471](https://infosec.exchange/@security_crawler_carl/117317305470834471) |
| **Développement logiciel / Crypto / Web3** | Développeurs freelance et professionnels blockchain/Web3 | Identifiants de portefeuilles crypto, fonds (1,7 milliard de yens), données d'authentification, accès aux systèmes des développeurs. | 30000 | [https://securityaffairs.com/199506/uncategorized/contagious-interview-30000-devices-infected-by-a-fake-job-interview.html](https://securityaffairs.com/199506/uncategorized/contagious-interview-30000-devices-infected-by-a-fake-job-interview.html) |
| **Gouvernement** | Kemendagri (Ministry of Home Affairs, Indonesia) | Noms, NIK (numéro d'identité indonésien), adresses. | Inconnu | [https://infosec.exchange/@AmmarSpaces/117316937696578708](https://infosec.exchange/@AmmarSpaces/117316937696578708) |
| **Éducation** | Vellore Institute of Technology (VIT) | Potentiellement : dossiers étudiants, données de candidats, informations employés, recherches, données financières. | Inconnu | [https://www.yazoul.net/intel/claim/2026-09-22-vit-vellore-ransomware-claim-by-auditteam-sep-2026](https://www.yazoul.net/intel/claim/2026-09-22-vit-vellore-ransomware-claim-by-auditteam-sep-2026)<br>[https://infosec.exchange/@Matchbook3469/117316375187022698](https://infosec.exchange/@Matchbook3469/117316375187022698) |
| **Gouvernement / Application** | FBI (via Oracle PeopleSoft) | Données sur les employés et les candidats (informations personnelles, etc.) | Inconnu | [https://www.bleepingcomputer.com/news/security/shinyhunters-claims-fbi-hack-data-theft-in-peoplesoft-zero-day-breach/](https://www.bleepingcomputer.com/news/security/shinyhunters-claims-fbi-hack-data-theft-in-peoplesoft-zero-day-breach/)<br>[https://infosec.exchange/@cloud/117317193962993359](https://infosec.exchange/@cloud/117317193962993359)<br>[https://infosec.exchange/@AmmarSpaces/117316895395863692](https://infosec.exchange/@AmmarSpaces/117316895395863692)<br>`hxxps://www[.]bleepingcomputer[.]com/news/security/shinyhunters-claims-fbi-hack-data-theft-in-peoplesoft-zero-day-breach/`<br>`hxxps://infosec[.]exchange/@AmmarSpaces/117316895395863692` |
| **Gouvernement / Application de la loi** | FBI | Noms, adresses personnelles, numéros de téléphone, dates de naissance, informations sur les conjoints, données de santé protégées, informations sur les candidats. | Environ 5 000 employés (échantillon), potentiellement 2-3 To de données | [https://infosec.exchange/@AmmarSpaces/117316856064853890](https://infosec.exchange/@AmmarSpaces/117316856064853890)<br>[https://en.killbait.com/fbi-hacked-cybersecurity-group-claims-to-steal-data-on-all-employees.html?utm_source=mastodon_social&utm_medium=social&utm_campaign=killbait.mastodon_social](https://en.killbait.com/fbi-hacked-cybersecurity-group-claims-to-steal-data-on-all-employees.html?utm_source=mastodon_social&utm_medium=social&utm_campaign=killbait.mastodon_social)<br>[https://mastodon.social/@killbait/117316542378520424](https://mastodon.social/@killbait/117316542378520424)<br>[https://techcrunch.com/2026/09/22/hacking-group-shinyhunters-claims-it-breached-the-fbi-stole-agents-and-applicants-data/](https://techcrunch.com/2026/09/22/hacking-group-shinyhunters-claims-it-breached-the-fbi-stole-agents-and-applicants-data/)<br>[https://osintsights.com/shinyhunters-breaches-fbi-exposes-employee-data-in-dispute-over-gangs-tactics?utm_source=mastodon&utm_medium=social](https://osintsights.com/shinyhunters-breaches-fbi-exposes-employee-data-in-dispute-over-gangs-tactics?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117315954290292964](https://mastodon.social/@Analyst207/117315954290292964) |
| **Gouvernement / Application de la loi** | FBI (Federal Bureau of Investigation) | Noms, adresses personnelles, numéros de téléphone, informations sur les conjoints, données sur les candidats. | Inconnu | [https://www.404media.co/we-hacked-the-fbi-hackers-say-they-have-data-on-all-fbi-employees/](https://www.404media.co/we-hacked-the-fbi-hackers-say-they-have-data-on-all-fbi-employees/)<br>[https://tldr.nettime.org/@remixtures/117316999232510706](https://tldr.nettime.org/@remixtures/117316999232510706) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-18169** | 9.9 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Traversée de chemin (Path Traversal) via validation incorrecte des liens symboliques (CWE-22) | Divulgation d'informations sensibles (fichiers de configuration, secrets, données métier) pouvant faciliter des mouvements latéraux ou une compromission plus profonde de la plateforme de transactions financières. | Theoretical | Désactiver le suivi des liens symboliques dans la configuration FTM, appliquer les correctifs éditeur IBM (bulletin node 7288641), revoir les configurations système pour corriger la validation incorrecte des chemins, et restreindre les privilèges des comptes authentifiés. | [https://cvefeed.io/vuln/detail/CVE-2026-18169](https://cvefeed.io/vuln/detail/CVE-2026-18169) |
| **CVE-2026-18163** | 9.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Désérialisation de données non fiables (CWE-502) menant à l'exécution de code arbitraire | Exécution de code arbitraire à distance sur le serveur FTM, pouvant conduire à une compromission totale de la plateforme de transactions financières, à un vol de données ou à une interruption de service. | Theoretical | Appliquer les correctifs éditeur IBM (bulletin node 7288641), mettre à jour IBM FTM vers la dernière version, sécuriser les processus de désérialisation en n'acceptant que des données fiables et revoir les méthodes d'entrée et de sérialisation. | [https://cvefeed.io/vuln/detail/CVE-2026-18163](https://cvefeed.io/vuln/detail/CVE-2026-18163) |
| **CVE-2026-18162** | 9.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Injection de code (CWE-94) via neutralisation incorrecte d'entrées utilisateur dans le constructeur Function | Exécution de code arbitraire à distance sur le serveur FTM, compromettant la confidentialité, l'intégrité et la disponibilité de la plateforme de transactions financières. | Theoretical | Mettre à jour IBM FTM for OpenShift vers la dernière version, appliquer les correctifs éditeur IBM (bulletin node 7288641) et revoir les mécanismes de validation des entrées utilisateur. | [https://cvefeed.io/vuln/detail/CVE-2026-18162](https://cvefeed.io/vuln/detail/CVE-2026-18162) |
| **CVE-2026-18154** | 8.0 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Utilisation d'une clé cryptographique codée en dur ou prévisible (CWE-321) | Divulgation d'informations sensibles par déchiffrement de données protégées par une clé prévisible, pouvant compromettre la confidentialité des transactions financières. | Theoretical | Supprimer les clés codées en dur ou prévisibles, utiliser des clés fortes générées dynamiquement, mettre en place des pratiques de gestion sécurisée des clés et appliquer les correctifs IBM (bulletin node 7288641). | [https://cvefeed.io/vuln/detail/CVE-2026-18154](https://cvefeed.io/vuln/detail/CVE-2026-18154) |
| **CVE-2026-18137** | 8.1 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Injection ESQL (CWE-89) par neutralisation incorrecte des éléments spéciaux | Exécution de commandes ESQL arbitraires pouvant conduire à la manipulation de données, à l'accès non autorisé à des ressources ou à une compromission de l'intégrité des transactions financières. | Theoretical | Mettre à jour IBM FTM vers une version neutralisant correctement les commandes ESQL, appliquer les correctifs éditeur IBM (bulletin node 7288641) et revoir la validation des entrées. | [https://cvefeed.io/vuln/detail/CVE-2026-18137](https://cvefeed.io/vuln/detail/CVE-2026-18137) |
| **CVE-2026-18131** | 8.2 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Cross-Site Scripting (XSS) par neutralisation incorrecte des entrées HTML (CWE-79) | Exécution de scripts malveillants dans le contexte de session d'un utilisateur authentifié, pouvant conduire au vol de session, à la manipulation d'opérations financières ou à la divulgation d'informations sensibles. | Theoretical | Mettre à jour IBM FTM vers la dernière version, appliquer les correctifs éditeur IBM (bulletin node 7288641), assainir toutes les entrées HTML et valider strictement les données fournies par l'utilisateur. | [https://cvefeed.io/vuln/detail/CVE-2026-18131](https://cvefeed.io/vuln/detail/CVE-2026-18131) |
| **CVE-2026-18095** | 8.5 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Débordement de tampon (CWE-787, écriture hors limites) menant à l'exécution de code arbitraire | Exécution de code arbitraire sur le serveur FTM, pouvant entraîner une compromission totale de la plateforme, un vol de données ou une interruption de service. | Theoretical | Mettre à jour IBM FTM vers la dernière version, appliquer les correctifs éditeur IBM (bulletin node 7288641) et revoir les configurations de sécurité pour corriger les faiblesses potentielles. | [https://cvefeed.io/vuln/detail/CVE-2026-18095](https://cvefeed.io/vuln/detail/CVE-2026-18095) |
| **CVE-2026-18074** | 8.2 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for RedHat OpenShift | Authentification incorrecte et autorisation manquante (CWE-287) | Exécution d'actions non autorisées sur la plateforme FTM, pouvant compromettre l'intégrité des transactions financières et entraîner une altération des données ou une interruption partielle de service. | Theoretical | Mettre à jour IBM FTM for OpenShift pour appliquer des contrôles d'authentification et d'autorisation corrects, vérifier la configuration des mécanismes d'authentification et s'assurer que les règles d'autorisation sont correctement implémentées (bulletin IBM node 7288641). | [https://cvefeed.io/vuln/detail/CVE-2026-18074](https://cvefeed.io/vuln/detail/CVE-2026-18074) |
| **CVE-2026-17647** | 8.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Inclusion de fonctionnalité provenant d'une sphère de contrôle non fiable (CWE-829) | Exécution de code arbitraire avec les privilèges du processus FTM, pouvant mener à la compromission du conteneur, à la modification de données transactionnelles et à un mouvement latéral dans le cluster OpenShift. Le score de confidentialité, d'intégrité et de disponibilité est élevé (C:H/I:H/A:H) avec un changement de périmètre de sécurité (S:C). | None | Appliquer les correctifs fournis par IBM via le bulletin node/7288641, vérifier et mettre à jour les composants tiers non fiables, revoir les paramètres de sécurité Red Hat OpenShift et restreindre les privilèges locaux accordés aux conteneurs FTM. | [https://cvefeed.io/vuln/detail/CVE-2026-17647](https://cvefeed.io/vuln/detail/CVE-2026-17647) |
| **CVE-2026-17646** | 8.5 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Restriction incorrecte des références d'entités externes XML (CWE-611, XXE) | Divulgation d'informations sensibles (fichiers locaux, secrets, données de configuration) avec un impact élevé sur la confidentialité et un impact limité sur l'intégrité. Le changement de périmètre (S:C) indique que l'impact peut s'étendre au-delà du composant vulnérable. | None | Désactiver le traitement des entités externes dans les parseurs XML, appliquer les correctifs IBM du bulletin node/7288641, restreindre l'accès aux informations sensibles et limiter les privilèges des comptes authentifiés. | [https://cvefeed.io/vuln/detail/CVE-2026-17646](https://cvefeed.io/vuln/detail/CVE-2026-17646) |
| **CVE-2026-17645** | 9.1 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Gestion incorrecte des privilèges (CWE-269) | Élévation de privilèges pouvant conduire à la compromission complète de l'application FTM et du cluster OpenShift sous-jacent, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité, et un changement de périmètre de sécurité. | None | Appliquer la dernière mise à jour IBM FTM for OpenShift, revoir et restreindre les privilèges utilisateurs, surveiller les journaux d'accès pour détecter toute activité suspecte et appliquer le principe du moindre privilège. | [https://cvefeed.io/vuln/detail/CVE-2026-17645](https://cvefeed.io/vuln/detail/CVE-2026-17645) |
| **CVE-2026-17644** | 8.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Utilisation d'identifiants codés en dur (CWE-798) | Accès non autorisé à des informations sensibles et altération de l'intégrité des données transactionnelles, avec un changement de périmètre de sécurité pouvant affecter d'autres composants de l'environnement OpenShift. | None | Identifier et supprimer les identifiants codés en dur, mettre en œuvre une gestion sécurisée des identifiants (coffre-fort de secrets, rotation), reconstruire et redéployer l'application, et appliquer les correctifs IBM du bulletin node/7288641. | [https://cvefeed.io/vuln/detail/CVE-2026-17644](https://cvefeed.io/vuln/detail/CVE-2026-17644) |
| **CVE-2026-17643** | 8.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Identifiants insuffisamment protégés (CWE-522) | Divulgation d'informations sensibles et exécution d'actions non autorisées avec les privilèges du compte compromis, avec un changement de périmètre de sécurité pouvant affecter l'ensemble de l'environnement FTM. | None | Restreindre l'accès aux identifiants sensibles, appliquer les mises à jour de sécurité de l'éditeur (bulletin node/7288641), revoir les configurations de contrôle d'accès et mettre en œuvre une gestion sécurisée des secrets. | [https://cvefeed.io/vuln/detail/CVE-2026-17643](https://cvefeed.io/vuln/detail/CVE-2026-17643) |
| **CVE-2026-17637** | 8.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Désérialisation de données non fiables (CWE-502) | Exécution de code arbitraire avec les privilèges du processus FTM, pouvant entraîner la compromission du conteneur, la manipulation de transactions financières et un mouvement latéral dans le cluster OpenShift. | None | Mettre à jour IBM FTM for OpenShift avec les correctifs de l'éditeur (bulletin node/7288641), sécuriser l'environnement applicatif, restreindre les accès réseau adjacents et surveiller les exécutions de code non autorisées. | [https://cvefeed.io/vuln/detail/CVE-2026-17637](https://cvefeed.io/vuln/detail/CVE-2026-17637) |
| **CVE-2026-17636** | 8.8 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Écriture hors limites (CWE-787) | Exécution de code arbitraire avec les privilèges du processus FTM, pouvant entraîner la compromission du conteneur, la corruption de données et un mouvement latéral dans l'environnement OpenShift. | None | Appliquer les correctifs IBM pour valider les entrées de quantité (bulletin node/7288641), mettre à jour IBM FTM for Red Hat OpenShift, restreindre les entrées de données non validées et surveiller le système pour détecter toute activité suspecte. | [https://cvefeed.io/vuln/detail/CVE-2026-17636](https://cvefeed.io/vuln/detail/CVE-2026-17636) |
| **CVE-2026-17635** | 9.1 | N/A | FALSE | IBM Financial Transaction Manager (FTM) for Red Hat OpenShift | Absence d'authentification pour une fonction critique (CWE-306) | Exécution d'actions non autorisées sur des fonctions critiques de FTM, avec un impact élevé sur la confidentialité et l'intégrité des données transactionnelles, sans impact direct sur la disponibilité. | None | Restreindre les méthodes HTTP selon les contraintes de sécurité, revoir et appliquer les contrôles d'accès pour les opérations sensibles, appliquer les recommandations de sécurité IBM et mettre à jour FTM vers la dernière version sécurisée (bulletin node/7288641). | [https://cvefeed.io/vuln/detail/CVE-2026-17635](https://cvefeed.io/vuln/detail/CVE-2026-17635) |
| **CVE-2026-7273** | 8.8 | N/A | TRUE | Zyxel GS1900 Series Switches (firmware, composant CGI) | Débordement de tampon basé sur la pile (stack-based buffer overflow) | Exécution de commandes OS arbitraires sur le switch par un attaquant LAN non authentifié, compromission complète de l'équipement, exfiltration de configurations, de hashes de credentials root et d'informations réseau. Risque de pivot vers d'autres segments réseau et de réutilisation des credentials exfiltrés. Score CVSS 8.8. | Active | Appliquer les firmwares corrigés (2.90(AAHH.2)C0, 2.90(AAHI.2)C0, 2.90(AAZI.2)C0, 2.90(AAHJ.2)C0, 2.90(AAHL.2)C0, 2.90(AAHK.2)C0, 2.90(ABTO.2)C0, 2.90(ABTP.2)C0, 2.90(AAHN.2)C0, 2.90(ABTQ.2)C0). Les agences fédérales civiles (FCEB) doivent appliquer les correctifs avant le 24 septembre 2026. En attendant, restreindre l'accès à l'interface de gestion aux réseaux d'administration de confiance, segmenter les switches, bloquer les flux TFTP sortants et réinitialiser les credentials potentiellement exposés. | [https://www.security.nl/posting/954121/CISA+meldt+actief+misbruik+van+stackoverflow+in+Zyxel+switch?channel=rss](https://www.security.nl/posting/954121/CISA+meldt+actief+misbruik+van+stackoverflow+in+Zyxel+switch?channel=rss)<br>[https://thehackernews.com/2026/09/zyxel-and-veeam-flaws-under-active.html](https://thehackernews.com/2026/09/zyxel-and-veeam-flaws-under-active.html)<br>[https://securityaffairs.com/199518/hacking/u-s-cisa-adds-zyxel-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/199518/hacking/u-s-cisa-adds-zyxel-flaw-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-32996** | 7.3 | N/A | FALSE | Veeam Agent for Microsoft Windows (jusqu'à la version 13.0.1.2067 et toutes les versions 13 antérieures) | Élévation de privilèges locale (local privilege escalation) | Un utilisateur local à faibles privilèges peut obtenir les privilèges NT AUTHORITY\SYSTEM sur un endpoint Windows, permettant une compromission complète de la machine. Le risque est particulièrement élevé sur les systèmes partagés par plusieurs utilisateurs locaux. Score CVSS 7.3. | Active | Mettre à jour Veeam Agent for Microsoft Windows vers une version corrigée (au-delà de 13.0.1.2067). En attendant, restreindre le nombre d'utilisateurs locaux sur les endpoints, limiter l'accès au service Veeam Endpoint Backup et surveiller les accès au named pipe gRPC. Révoquer les credentials des comptes locaux potentiellement compromis. | [https://thehackernews.com/2026/09/zyxel-and-veeam-flaws-under-active.html](https://thehackernews.com/2026/09/zyxel-and-veeam-flaws-under-active.html)<br>[https://securityaffairs.com/199532/security/public-poc-exposes-critical-veeam-agent-privilege-escalation.html](https://securityaffairs.com/199532/security/public-poc-exposes-critical-veeam-agent-privilege-escalation.html) |
| **CVE-2026-94127** | 9.8 | N/A | FALSE | F5 BIG-IP APM (versions 17.1.0-17.1.3, 17.5.0-17.5.1, 21.1.0) configurées avec une access policy APM et un profil OAuth sur un serveur virtuel | Débordement de tampon basé sur le tas (heap-based buffer overflow) | Exécution de code à distance non authentifiée sur les systèmes BIG-IP APM exposés, compromission complète de la passerelle d'authentification, avec risque d'accès aux applications, portails web, services VPN et ressources protégées. Les déploiements exposés sur Internet sont les plus critiques. Score CVSS 9.8. | Active | Appliquer les hotfixs F5 : Hotfix-BIGIP-21.1.0.2.0.30.22 (21.1.0), Hotfix-BIGIP-17.5.1.9.0.160.12 (17.5.0-17.5.1), Hotfix-BIGIP-17.1.3.5.0.41.14 (17.1.0-17.1.3). Si le correctif ne peut être appliqué immédiatement, F5 fournit une mitigation basée sur iRule à appliquer sur le serveur virtuel affecté (à obtenir auprès du support F5). Préserver les preuves forensiques, vérifier les signes de compromission et engager la réponse à incident si nécessaire. | [https://cert.europa.eu/publications/security-advisories/2026-013/](https://cert.europa.eu/publications/security-advisories/2026-013/)<br>[https://fieldeffect.com/blog/f5-fixes-big-ip-apm-vulnerability](https://fieldeffect.com/blog/f5-fixes-big-ip-apm-vulnerability) |
| **CVE-2026-17102** | 8.8 | N/A | FALSE | IBM DataStage on Cloud Pak for Data 5.4.0.0 | Injection de commandes OS (CWE-78 : neutralisation incorrecte d'éléments spéciaux utilisés dans une commande OS) | Exécution de commandes arbitraires sur le système hébergeant DataStage par un attaquant distant authentifié, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. Score CVSS 8.8. | Theoretical | Mettre à jour IBM DataStage on Cloud Pak for Data vers une version corrigée. Appliquer les mises à jour de sécurité fournies par IBM (https://www[.]ibm[.]com/support/pages/node/7288649). Restreindre les privilèges des utilisateurs pouvant exécuter des commandes et assurer une neutralisation correcte des éléments de commandes OS. | [https://cvefeed.io/vuln/detail/CVE-2026-17102](https://cvefeed.io/vuln/detail/CVE-2026-17102) |
| **CVE-2026-16672** | 8.8 | N/A | FALSE | IBM DataStage on Cloud Pak for Data 5.4.0.0 | Injection de commandes OS (CWE-78 : neutralisation incorrecte d'éléments spéciaux utilisés dans une commande OS) | Exécution de code arbitraire sur le système hébergeant DataStage par un attaquant distant authentifié, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. Score CVSS 8.8. | Theoretical | Mettre à jour IBM DataStage on Cloud Pak for Data vers une version corrigée. Appliquer les mises à jour de sécurité fournies par IBM (https://www[.]ibm[.]com/support/pages/node/7288649). Restreindre les privilèges des utilisateurs pouvant exécuter des commandes et assurer une neutralisation correcte des éléments de commandes OS. | [https://cvefeed.io/vuln/detail/CVE-2026-16672](https://cvefeed.io/vuln/detail/CVE-2026-16672) |
| **CVE-2026-93616** | 9.8 | N/A | FALSE | Check Point Security Management Server, Multi-Domain Security Management Server, Log Server, Multi-Domain Log Server et SmartEvent | Traversée de répertoire (path traversal) dans le service web du serveur de management, permettant à un attaquant non authentifié de téléverser puis d'exécuter des scripts | Compromission du serveur de management qui centralise les politiques de sécurité, l'activité d'administration et les journaux de l'ensemble du déploiement Check Point. Une compromission peut permettre la modification des politiques de filtrage, la désactivation de protections, l'accès aux journaux et une propagation latérale à l'ensemble du réseau géré. | Active | Appliquer le correctif indiqué dans l'article support Check Point sk1000171 après vérification de la version et du niveau de Jumbo Hotfix. En attendant, restreindre l'accès au serveur via SmartConsole (Manage & Settings → Permissions & Administrators → Trusted Clients) et/ou un filtrage pare-feu. Utiliser les guides de chasse et les IOC de sk1000171 pour vérifier si le serveur a été compromis avant le correctif, l'installation du patch ne permettant pas de conclure sur une exploitation antérieure. | [https://thehackernews.com/2026/09/check-point-warns-of-management-server.html](https://thehackernews.com/2026/09/check-point-warns-of-management-server.html)<br>[https://securityaffairs.com/199549/security/check-point-fixes-a-new-actively-exploited-critical-security-flaw.html](https://securityaffairs.com/199549/security/check-point-fixes-a-new-actively-exploited-critical-security-flaw.html) |
| **CVE-2026-87902** | 9.2 | N/A | FALSE | WordPress core, versions 4.7.0 à 7.1.1 incluses | Traversée de répertoire dans la sélection du fichier de gabarit, pouvant conduire à l'exécution de code sur certains serveurs | Chargement de fichiers PHP locaux hors périmètre de thème et, sur les configurations exposées, exécution de code arbitraire sur le serveur web, avec pour conséquence une compromission potentielle du site et de l'hébergement. | None | Mettre à jour vers 7.1.2 (branche 7.1.x), 7.0.6, 6.9.9, 6.8.10, 6.7.9 ou 6.6.9 selon la branche utilisée ; les versions plus anciennes sont corrigées jusqu'à 4.7.37. Aucun contournement n'est proposé par l'éditeur : la mise à jour constitue la seule remédiation. Les sites avec mises à jour automatiques activées seront corrigés automatiquement. | [https://thehackernews.com/2026/09/wordpress-issues-patch-for-critical.html](https://thehackernews.com/2026/09/wordpress-issues-patch-for-critical.html) |
| **CVE-2026-90898** | 9.8 | N/A | FALSE | Bifrost, passerelle IA open source (transport HTTP), toutes versions antérieures à 2.1.0 lorsque l'authentification de management est désactivée (configuration par défaut) | Exécution de code à distance non authentifiée via l'enregistrement d'un client MCP de type stdio | Exécution de commandes arbitraires sur le serveur de la passerelle avec les privilèges du processus, accès aux clés API des fournisseurs LLM connectés, et compromission potentielle de l'ensemble des flux IA transitant par la passerelle. | None | Mettre à niveau vers transports/v2.1.0 (qui renvoie 403 pour l'enregistrement non authentifié d'un client MCP stdio). Si la mise à niveau immédiate est impossible, activer governance.auth_config.is_enabled, utiliser des identifiants forts et maintenir l'écouteur de management hors des réseaux non maîtrisés. Toute instance ayant fonctionné avec l'authentification désactivée et l'API exposée doit être considérée comme compromise, avec rotation des clés virtuelles et des clés API fournisseurs. | [https://thehackernews.com/2026/09/critical-bifrost-ai-gateway-flaw-lets.html](https://thehackernews.com/2026/09/critical-bifrost-ai-gateway-flaw-lets.html)<br>[https://thehackernews.com/2026/09/critical-bifrost-ai-gateway-flaw-lets/](https://thehackernews.com/2026/09/critical-bifrost-ai-gateway-flaw-lets/) |
| **CVE-2026-28326** | N/A | N/A | FALSE | SolarWinds Access Rights Manager versions antérieures à 2026.2.1 | Exécution de code arbitraire à distance | Exécution de code arbitraire à distance sur le serveur hébergeant Access Rights Manager, pouvant conduire à la compromission de l'outil de gestion des accès et, par extension, des systèmes et comptes qu'il administre. | None | Mettre à jour Access Rights Manager vers la version 2026.2.1 ou supérieure, conformément au bulletin de sécurité SolarWinds cve-2026-28326 du 17 septembre 2026. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1211/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1211/) |
| **CVE-2026-19202** | 9.1 | N/A | FALSE | mcp-toolbox-sdk-python (paquet toolbox-core) | Utilisation d'un cache contenant des informations sensibles (CWE-524) — réutilisation de jeton entre audiences | Score CVSS 4.0 de 9,1 (CRITIQUE). Usurpation d'identité applic{   "vulnerabilities": [     {       "cve_id": "CVE-2026-19202 | Theoretical |  | [https://cvefeed.io/vuln/detail/CVE-2026-19202](https://cvefeed.io/vuln/detail/CVE-2026-19202) |
| **CVE-2026-86296** | N/A | N/A | FALSE | D-Link DIR-822A (firmware A_101) | Débordement de pile (stack overflow) dans le traitement des paquets DHCP | Exécution de code arbitraire sur le routeur, prise de contrôle complet de l'équipement, interception ou redirection du trafic réseau, compromission du réseau local. | Theoretical | Éviter d'exposer le routeur inutilement sur Internet, limiter le remote management et restreindre l'accès administratif par filtrage firewall. Surveiller la publication d'un firmware correctif par D-Link et remplacer l'équipement si aucun correctif n'est disponible. | [https://www.security.nl/posting/954188/D-Link+waarschuwt+voor+kritieke+kwetsbaarheid+in+wifi-router?channel=rss](https://www.security.nl/posting/954188/D-Link+waarschuwt+voor+kritieke+kwetsbaarheid+in+wifi-router?channel=rss) |
| **CVE-2026-86510** | N/A | N/A | FALSE | D-Link DIR-822A (firmware A_101) | Écriture hors limites (out-of-bounds write) dans le traitement des paquets L2TP | Impact encore incertain : corruption mémoire, déni de service ou exécution de code arbitraire sur l'équipement selon les analyses en cours. | Theoretical | Éviter d'exposer le routeur inutilement sur Internet, limiter le remote management et restreindre l'accès administratif par filtrage firewall. Surveiller les communications de D-Link concernant un firmware correctif. | [https://www.security.nl/posting/954188/D-Link+waarschuwt+voor+kritieke+kwetsbaarheid+in+wifi-router?channel=rss](https://www.security.nl/posting/954188/D-Link+waarschuwt+voor+kritieke+kwetsbaarheid+in+wifi-router?channel=rss) |
| **CVE-2026-93952** | 10.0 | N/A | FALSE | VeloCloud Orchestrator (VCO) on-premises - trains 5.2 (5.2.3.15 et antérieurs), 6.1 (6.1.3.7 et antérieurs), 6.4 (6.4.2.7 et antérieurs), 7.0 (7.0.0.2 et antérieurs) | Vulnérabilité permettant à un attaquant distant non authentifié d'accéder à des fonctions internes privilégiées et d'affecter l'hôte VCO | Compromission de l'orchestrateur et des données qu'il gère, accès potentiel aux Edge devices managés, installation de webshells et de démons backdoor, persistance via services systemd. | Active | Appliquer les versions corrigées (5.2.3.16+, 6.4.2.8+) ou contacter le TAC Arista pour les trains non supportés. En attendant : limiter l'accès à l'interface web du VCO aux réseaux d'administration de confiance, surveiller les accès depuis des IP malveillantes connues, surveiller le trafic sortant inattendu, bloquer les ports sortants non nécessaires, rechercher les démons backdoor et webshells, et revoir l'activité administrative récente. | [https://thehackernews.com/2026/09/new-cvss-100-velocloud-orchestrator.html](https://thehackernews.com/2026/09/new-cvss-100-velocloud-orchestrator.html) |
| **CVE-2026-89775** | 9.3 | N/A | FALSE | Noyau Linux (code KVM pour ARM64) - corrigé dans Linux 6.18.51, 7.2.5 et 7.3-rc1 | Accès en lecture-écriture à la mémoire de l'hôte depuis un invité KVM ARM64 (invalidation TLB manquée) | Évasion de machine virtuelle, exécution de code sur l'hôte, accès en lecture-écriture à la mémoire du noyau hôte. Sur les systèmes où /dev/kvm est accessible à tous les utilisateurs (par exemple RHEL par défaut), un utilisateur local peut obtenir les privilèges root. | Theoretical | Appliquer les correctifs noyau (Linux 6.18.51, 7.2.5, 7.3-rc1) ou les mises à jour des distributions. Red Hat indique qu'aucune mesure d'atténuation ne répond à ses critères de contournement. La seule certitude est le périmètre : l'attaque ne cible que les hôtes avec virtualisation imbriquée activée, ce qui n'est pas la configuration par défaut sur ARM64. | [https://thehackernews.com/2026/09/new-linux-kernel-flaw-gives-arm64-kvm.html](https://thehackernews.com/2026/09/new-linux-kernel-flaw-gives-arm64-kvm.html) |
| **CVE-2026-65660** | 8.8 | N/A | FALSE | Microsoft SharePoint Server 2016, 2019 et Subscription Edition (SharePoint 2013 également affecté selon le chercheur, mais hors support) | CWE-94 - Injection de code (exécution de code à distance authentifiée via désérialisation) | Exécution de code à distance sur le serveur SharePoint, déploiement de webshells en mémoire, compromission potentielle pré-authentification en chaîne avec un contournement d'authentification. | Theoretical | Appliquer les mises à jour de sécurité du 11 août 2026, qui corrigent la faille et désactivent la fonction vulnérable par défaut. S'assurer que le correctif du 9 juin 2026 pour le contournement d'authentification est appliqué. Désactiver l'accès anonyme aux pages SharePoint si non nécessaire. | [https://thehackernews.com/2026/09/sharepoint-flaw-initially-listed-as.html](https://thehackernews.com/2026/09/sharepoint-flaw-initially-listed-as.html) |
| **CVE-2026-26980** | N/A | N/A | FALSE | Ghost (CMS) | Injection SQL critique | Accès non autorisé à la base de données, extraction ou modification de données sensibles, compromission potentielle de l'instance Ghost. | Active | Appliquer le correctif pour CVE-2026-26980 et mettre à jour Ghost CMS. Déployer des règles WAF contre les injections SQL et restreindre l'exposition des interfaces d'administration. | [https://www.security.nl/posting/954128/Slechts+%C3%A9%C3%A9n+van+225+aan+Anthropic+gelinkte+kwetsbaarheden+actief+misbruikt?channel=rss](https://www.security.nl/posting/954128/Slechts+%C3%A9%C3%A9n+van+225+aan+Anthropic+gelinkte+kwetsbaarheden+actief+misbruikt?channel=rss) |
| **CVE-2026-93485** | 7.1 | N/A | FALSE | WordPress core (versions 4.7 à 7.1) | XSS stocké via commentaire menant à une exécution de code à distance (RCE) par session administrateur | Exécution de code arbitraire sur le serveur WordPress via l'upload d'un plugin malveillant, prise de contrôle complète du site, vol de données, défiguration, pivot vers d'autres systèmes. Le vecteur initial est un simple commentaire anonyme, ce qui abaisse fortement la barrière d'exploitation. | None | Mettre à jour vers WordPress 7.1.1 (branche 7.1), 7.0.5 (branche 7.0), 6.9.8 (branche 6.9) ou la version corrigée de la branche concernée jusqu'à 4.7.36. En cas d'impossibilité immédiate, désactiver les commentaires sur le site ou sur les articles exposés et s'appuyer sur un WAF ou un plugin de sécurité pour bloquer les commentaires malveillants. La mise à jour corrige la faille mais n'annule pas les modifications déjà effectuées par un attaquant : rechercher les plugins et fichiers non reconnus. | [https://thehackernews.com/2026/09/wordpress-comment2shell-flaw-can-turn.html](https://thehackernews.com/2026/09/wordpress-comment2shell-flaw-can-turn.html) |
| **CVE-2026-20350** | 7.2 | N/A | FALSE | Cisco ThousandEyes Virtual Appliance | Injection de commandes OS (Remote Code Execution) | Exécution de code arbitraire en tant que root sur l'appliance virtuelle, permettant la compromission totale du système, la modification de la configuration de supervision, le pivot vers le réseau interne et la falsification des données de monitoring. | None | Appliquer la mise à jour publiée par Cisco dans l'avis cisco-sa-teva-os-command-W4GAO6jp. En attendant, restreindre strictement l'accès authentifié à l'appliance et limiter l'exposition réseau de l'interface DHCP et d'administration. | [http://www.zerodayinitiative.com/advisories/ZDI-26-719/](http://www.zerodayinitiative.com/advisories/ZDI-26-719/) |
| **CVE-2026-94450** | N/A | N/A | FALSE | s2n-quic (implémentation Rust du protocole QUIC), versions <= 1.88.0 | Déni de service par validation incorrecte de la longueur du Destination Connection ID | Déni de service : arrêt d'un point de terminaison serveur QUIC par un seul paquet UDP, entraînant une indisponibilité de service pour les applications s'appuyant sur s2n-quic configuré avec l'émission de paquets Retry. | None | Mettre à niveau vers s2n-quic 1.89.0 et s'assurer que tout code forké ou dérivé intègre le correctif. Aucun workaround n'est disponible ; la mise à niveau est la seule remédiation recommandée. | [https://aws.amazon.com/security/security-bulletins/rss/2026-116-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-116-aws/) |
| **CVE-2026-94384** | N/A | N/A | FALSE | AmazonConnectSalesforceLambda (application Serverless Application Repository), versions >= 5.15 et <= 5.24.16 | Autorisation manquante (Missing Authorization) dans la fonction Lambda sfExecuteAWSService | Élévation de privilèges au sein du compte AWS : un principal IAM à faibles privilèges peut contourner ses restrictions et exécuter des opérations AWS privilégiées, avec un risque de compromission de ressources, de modification de configuration et de mouvement latéral dans l'environnement cloud. | None | Mettre à niveau vers AmazonConnectSalesforceLambda 5.26 ou ultérieur. Après l'installation, supprimer ou désactiver la fonction sfExecuteAWSService. Si elle est conservée, n'accorder lambda:InvokeFunction qu'à l'unique utilisateur IAM du CTI Adapter (avec SCP ou permission boundary refusant tous les autres principaux) et définir le paramètre SalesforceExecuteAWSServiceUser sur ce même utilisateur afin de limiter les invocations cross-account. | [https://aws.amazon.com/security/security-bulletins/rss/2026-115-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-115-aws/) |
| **CVE-2026-84077** | 8.1 | N/A | FALSE | IBM Guardium Data Protection 12.2 | Cross-Site Request Forgery (CSRF) | Contournement des restrictions de sécurité de la plateforme de protection des données, avec un risque de modification de politiques, d'exposition de données sensibles et de compromission de la supervision de sécurité des bases de données. | None | Aucun correctif disponible. Isoler les instances Guardium du réseau non fiable, restreindre l'accès aux consoles d'administration, renforcer l'authentification, segmenter le réseau et surveiller étroitement les actions administratives. Suivre la publication d'un correctif IBM. | [https://www.valtersit.com/cve/CVE-2026-84077/](https://www.valtersit.com/cve/CVE-2026-84077/) |
| **CVE-2026-61721** | 8.0 | N/A | FALSE | FluidSynth (bibliothèque de synthèse audio), versions antérieures à 2.5.6 | Lecture hors limites (out-of-bounds read) via un fichier DLS forgé | Divulgation d'informations sensibles présentes en mémoire et déni de service par crash de l'application traitant le fichier DLS malveillant. | None | Mettre à jour vers FluidSynth 2.5.6 ou ultérieur. Éviter de traiter des fichiers DLS provenant de sources non fiables et valider les fichiers audio importés. | [https://www.valtersit.com/cve/CVE-2026-61721/](https://www.valtersit.com/cve/CVE-2026-61721/) |
| **** | N/A | N/A | FALSE | Microsoft Defender (Antimalware Platform) sur Windows | Déni de service par épuisement de l'espace disque bloquant les mises à jour de plateforme et de signatures (aucun CVE attribué) | Defender continue de fonctionner mais son contenu de détection devient obsolète, réduisant la capacité de détection des menaces sur le poste. L'échec de mise à jour peut ne pas générer d'alerte automatique, ce qui rend la dégradation silencieuse. | Theoretical | Aucun correctif ni contournement éditeur. Vérifier la fraîcheur des signatures et de la plateforme Defender (Windows Security ou Get-MpComputerStatus), surveiller les échecs répétés de mise à jour, la faible espace disque sur le volume système et les fichiers cachés volumineux dans les répertoires temporaires. Restreindre l'exécution de binaires inconnus via WDAC ou AppLocker. | [https://thehackernews.com/2026/09/researcher-drops-bigdiskbuster-zero-day.html](https://thehackernews.com/2026/09/researcher-drops-bigdiskbuster-zero-day.html) |
| **** | N/A | N/A | FALSE | Moodle versions 5.0.x antérieures à 5.0.10, 5.1.x antérieures à 5.1.7, 5.2.x antérieures à 5.2.3 et versions antérieures à 4.5.14 | Injection SQL (SQLi) et contournement de la politique de sécurité | Injection SQL pouvant conduire à la divulgation ou à la modification de données de la plateforme d'apprentissage, et contournement de la politique de sécurité permettant un accès non autorisé à des fonctionnalités ou ressources. | None | Se référer aux bulletins de sécurité Moodle 482607 et 482608 du 22 septembre 2026 pour l'obtention des correctifs et appliquer les mises à jour vers les versions corrigées des branches concernées. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1210/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1210/) |
| **** | N/A | N/A | FALSE | Routeurs MikroTik (analyse technique MikroTrick) | Analyse technique de malware et processus de divulgation (aucun CVE identifié dans la source) | Non déterminé à partir de la source fournie ; se référer à l'analyse technique complète du CERT.PL. | None | Consulter l'analyse technique du CERT.PL et appliquer les recommandations de durcissement des routeurs MikroTik. Maintenir les firmwares à jour et restreindre l'exposition des interfaces d'administration. | [https://cert.pl/en/posts/2026/09/mikrotrick-technical-analysis/](https://cert.pl/en/posts/2026/09/mikrotrick-technical-analysis/) |
| **** | N/A | N/A | FALSE | Microsoft Defender (mécanisme de mise à jour de plateforme et de signatures) sur Windows | Déni de service sur le mécanisme de mise à jour de l'antivirus (zero-day, sans CVE identifié) | Blocage des mises à jour de plateforme et de signatures de Microsoft Defender, entraînant une dégradation de la capacité de détection et une exposition accrue aux menaces. Un attaquant peut exploiter cette fenêtre pour déployer des charges malveillantes non détectées. | Theoretical | Aucun correctif éditeur disponible à ce stade. Surveiller l'état des mises à jour Defender, bloquer l'exécution des binaires PoC via des politiques d'application (WDAC/AppLocker), isoler les machines affectées et appliquer des contrôles compensatoires. Suivre les communications de Microsoft pour un correctif. | [https://securityaffairs.com/199538/hacking/chaotic-eclipse-released-bigdiskbuster-a-poc-for-windows-defender-update-dos-zero-day.html](https://securityaffairs.com/199538/hacking/chaotic-eclipse-released-bigdiskbuster-a-poc-for-windows-defender-update-dos-zero-day.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="la-verite-sur-get-et-les-normes-http-mardi-22-septembre"></div>

## La vérité sur GET et les normes HTTP, (mardi 22 septembre)

### Résumé

L'article revient sur la méthode HTTP Query récemment introduite, qui permet d'envoyer une requête de type GET avec un corps. L'auteur rappelle que RFC2616 (section 4.3) interdisait explicitement un message-body si la méthode ne l'autorisait pas, et que RFC7231 (section 4.3.2) précise qu'un payload dans une requête GET n'a pas de sémantique définie et peut être rejeté par certaines implémentations. Des tests ont été menés sur plusieurs serveurs : Apache 2.4.68 accepte le corps et le transmet au script CGI (retour 200, CONTENT_LENGTH = 6, BODY = TEST) ; NGINX ignore le corps et répond 301 ; le serveur Python http.server ignore le corps et répond 200 ; Node ignore l'en-tête Content-Length et traite la requête sans erreur ; lighttpd 1.4.74 renvoie une erreur 400 et refuse la requête ; Tomcat ignore Content-Length et renvoie 200. L'auteur invite la communauté à tester d'autres serveurs.

---

### Analyse opérationnelle

Les divergences d'interprétation d'une requête GET avec corps entre proxy, WAF, CDN et serveur d'origine constituent une surface d'attaque classique de désynchronisation de requêtes (request smuggling) et de contournement de contrôles de sécurité. Un équipement de bordure qui ignore le corps alors que l'origine l'interprète (ou inversement) peut permettre de faire passer des charges non inspectées, d'empoisonner un cache ou de contourner des règles d'authentification. Les équipes SOC doivent vérifier la cohérence de parsing sur toute la chaîne HTTP et journaliser les GET porteurs d'un Content-Length ou Transfer-Encoding. Les CGI et scripts exposés qui interprètent un corps de GET sont particulièrement à risque.

---

### Implications stratégiques

Cet article illustre une dette normative persistante du protocole HTTP : l'absence de sémantique définie pour le corps d'un GET laisse chaque éditeur libre, ce qui fragmente la sécurité des architectures multi-couches. Pour les organisations exposant des applications web critiques, la maîtrise du comportement des middlewares devient un enjeu de conformité et de résilience, et non un simple détail d'implémentation. La généralisation de la méthode HTTP Query pourrait, à terme, standardiser ces échanges mais aussi élargir la surface d'attaque si les équipements de sécurité ne sont pas mis à jour.

---

### Recommandations

* Cartographier le comportement GET+body de chaque composant HTTP (proxy, WAF, CDN, serveur d'origine, framework applicatif).
* Normaliser ou rejeter les requêtes GET contenant un corps au niveau de la bordure.
* Ajouter des règles de détection sur les GET avec Content-Length/Transfer-Encoding non nuls.
* Tester régulièrement la cohérence de parsing entre proxy et origine pour détecter les désynchronisations.
* Limiter l'exposition des CGI et scripts hérités qui interprètent un corps de requête GET.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les serveurs web, reverse proxies, WAF et CDN en frontal et documenter leur comportement face à une requête GET contenant un corps (Content-Length / Transfer-Encoding).
* Établir une matrice de conformité RFC2616 vs RFC7231 vs méthode HTTP Query pour chaque brique de la chaîne de traitement.
* Définir une politique de normalisation des requêtes (rejet ou strip du corps sur GET) et la pousser sur les équipements de bordure.

#### Phase 2 — Détection et analyse

* Journaliser et alerter sur les requêtes GET portant un en-tête Content-Length ou Transfer-Encoding non nul.
* Surveiller les divergences de réponse entre proxy et serveur d'origine (200 vs 301 vs 400) sur la même requête, indicateur de désynchronisation.
* Corréler les anomalies de parsing HTTP avec des tentatives d'accès à des endpoints sensibles ou des CGI.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer au niveau WAF/proxy les requêtes GET avec corps jusqu'à validation du comportement applicatif.
* Isoler les serveurs dont le comportement diverge fortement (ex. lighttpd renvoyant 400 vs Apache acceptant le corps) et forcer une normalisation en amont.
* Révoquer les sessions ou tokens suspects si une désynchronisation de requêtes est confirmée.

#### Phase 4 — Activités post-incident

* Mettre à jour les règles de normalisation HTTP et les tests de non-régression protocolaire.
* Documenter les écarts de conformité RFC constatés et les remonter aux éditeurs concernés.
* Revoir la configuration des CGI et scripts exposés qui interprètent un corps de requête GET.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement dans les logs HTTP les requêtes GET avec corps sur les 90 derniers jours.
* Chercher des motifs de cache poisoning ou de contournement d'authentification corrélés à ces requêtes.
* Tester périodiquement la chaîne proxy/origine avec des requêtes GET+body pour détecter toute dérive de configuration.

---

### Sources

* [https://isc.sans.edu/diary/rss/33358](https://isc.sans.edu/diary/rss/33358)


---

<div id="analyse-de-lausivloader-ou-comment-transmettre-des-donnees-entre-les-etapes-dun-malware-jeudi-17-septembre"></div>

## Analyse de LausivLoader, ou comment transmettre des données entre les étapes d'un malware, (jeudi 17 septembre)

### Résumé

Fin août, un message de malspam a été mis en quarantaine par la passerelle mail d'un client. Le message demandait au destinataire de revoir des exigences jointes et de fournir un devis pour un système de fibre optique, en usurpant l'identité d'un employé d'une entreprise légitime. La passerelle a détecté du contenu malveillant dans la pièce jointe, et les contrôles SPF et DMARC auraient de toute façon bloqué le message. L'archive jointe portait l'extension .r01 et contenait un fichier d'environ 613 Ko nommé « PO.4843293191 For Supply Chain - Imports HM..js », détecté 28/55 sur VirusTotal et attribué à la famille LausivLoader. Le script contient 450 lignes de commentaires en mots anglais aléatoires ; après suppression, environ 205 Ko de code légèrement obfusqué construisent de longues chaînes. L'analyse par la fin du fichier révèle une commande construite via String.fromCharCode et une grande chaîne, exécutée en dernière ligne. Le code copie aussi le JavaScript ailleurs, tente d'enregistrer une tâche planifiée et écrit deux autres fichiers. La commande déobfusquée lance : C:\Windows\System32\conhost.exe --headless "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -NonI -W Hidden -EncodedCommand <Base64>. Le script PowerShell décodé charge des fichiers depuis les chemins stockés dans deux variables d'environnement (Kv7408 et Kv562), un mécanisme inhabituel de passage de données entre étapes du malware.

---

### Analyse opérationnelle

La chaîne d'infection combine un leurre métier crédible (devis fibre optique, supply chain), une archive à extension exotique pour contourner les filtres, un script JavaScript fortement obfusqué et une exécution PowerShell encodée lancée via conhost.exe --headless pour masquer la fenêtre. Les points de détection prioritaires sont : conhost.exe lançant powershell.exe avec -EncodedCommand, la création de tâches planifiées, la duplication de scripts JS dans des répertoires non standards et l'usage de variables d'environnement comme canal de transfert inter-étapes. Le fait que SPF et DMARC aient échoué montre que le durcissement de l'authentification mail reste un contrôle efficace, mais la détection de contenu en pièce jointe demeure indispensable. L'analyse doit se faire en laissant le code se déobfusquer lui-même dans un environnement isolé plutôt qu'à la main.

---

### Implications stratégiques

Le ciblage de fonctions achats/supply chain avec des leurres de devis industriels illustre la professionnalisation du malspam et la volonté d'obtenir un premier accès dans des chaînes d'approvisionnement sensibles. L'usage de loaders multi-étapes avec passage de données par variables d'environnement complique l'analyse statique et la détection par signature, ce qui pousse les organisations à investir dans la détection comportementale et la journalisation PowerShell. Pour les secteurs industriel et logistique, la compromission d'un poste achats peut servir de tremplin vers des fraudes au fournisseur ou des intrusions plus profondes.

---

### Recommandations

* Bloquer les archives multi-volumes et les scripts .js en pièce jointe au niveau de la passerelle mail.
* Activer la journalisation PowerShell (Script Block Logging, Module Logging) et la transmission vers le SIEM.
* Restreindre l'exécution de conhost.exe --headless et de PowerShell en mode encodé via WDAC/AppLocker.
* Analyser les scripts obfusqués en environnement isolé en laissant le code se décoder lui-même.
* Sensibiliser les équipes achats et supply chain aux leurres de demande de devis.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Durcir les passerelles de messagerie : blocage des archives exotiques (.r01, .r02, .rar multi-volumes) et des scripts .js/.jse en pièce jointe.
* Activer et valider les contrôles SPF, DKIM et DMARC en mode rejet sur tous les domaines de l'organisation.
* Restreindre l'exécution de conhost.exe --headless et de PowerShell en mode -EncodedCommand via AppLocker/WDAC et politiques de contrainte de langage.
* Préparer une sandbox d'analyse de scripts JavaScript et un poste d'analyse isolé pour le déobfuscation.

#### Phase 2 — Détection et analyse

* Alerter sur les processus conhost.exe lançant powershell.exe avec les arguments -NoP -NonI -W Hidden -EncodedCommand.
* Détecter la création de tâches planifiées pointant vers des fichiers .js ou des scripts dans des répertoires utilisateur/temp.
* Surveiller l'apparition de variables d'environnement inhabituelles (ex. noms aléatoires type Kv7408, Kv562) utilisées comme canal de passage de données entre étapes.
* Détecter l'écriture de fichiers JavaScript dupliqués dans des répertoires non standards et les exécutions wscript/cscript associées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement le poste ayant exécuté la pièce jointe et bloquer le hash du script au niveau EDR et passerelle mail.
* Supprimer les tâches planifiées créées et les fichiers déposés (script JS copié, fichiers annexes).
* Révoquer les sessions et identifiants présents sur la machine compromise et forcer une réinitialisation des secrets.
* Bloquer les domaines et adresses de C2 identifiés lors de l'analyse de la commande PowerShell décodée.

#### Phase 4 — Activités post-incident

* Publier les indicateurs (hash du .js, nom de l'archive, arguments de ligne de commande) dans les outils de détection internes.
* Revoir les règles de filtrage mail et les taux de quarantaine sur les pièces jointes de type archive/script.
* Former les utilisateurs ciblés (achats, supply chain) aux leurres de type demande de devis / appels d'offres.
* Documenter la chaîne d'exécution multi-étapes pour enrichir les playbooks de réponse.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement les exécutions de conhost.exe --headless avec PowerShell encodé sur 90 jours.
* Chercher les tâches planifiées créées par des processus non signés ou depuis des répertoires utilisateur.
* Rechercher les variables d'environnement créées de façon transitoire par des scripts et les accès fichiers associés.
* Corréler avec les journaux de passerelle mail pour identifier d'autres destinataires ayant reçu la même campagne.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Phishing par pièce jointe (archive .r01 contenant un script JavaScript) |
| **T1059.007** | Exécution de code via JavaScript/JScript |
| **T1059.001** | Exécution de PowerShell avec commande encodée en Base64 |
| **T1027** | Obfuscation du script par commentaires aléatoires et construction de chaînes |
| **T1053.005** | Création d'une tâche planifiée pour la persistance |
| **T1140** | Décodage/déobfuscation de la charge utile au moment de l'exécution |

---

### Sources

* [https://isc.sans.edu/diary/rss/33348](https://isc.sans.edu/diary/rss/33348)


---

<div id="campagnes-de-phishing-par-code-dappareil-csuite-cible-les-organisations-americaines-et-de-lue-et-analyse-des-causes-profondes-deviltokens"></div>

## Campagnes de phishing par code d'appareil : CSuite cible les organisations américaines et de l'UE et analyse des causes profondes d'EvilTokens

### Résumé

Deux publications traitent de l'exploitation du flux d'authentification par code d'appareil (device code) à des fins de phishing. La première décrit la campagne CSuite, qui cible des organisations aux États-Unis et dans l'Union européenne en combinant hameçonnage par code d'appareil et accès distant. La seconde, publiée par Microsoft, analyse la campagne EvilTokens et remonte à la racine du problème du device code phishing ; elle mentionne également la Cloud Web Applications Threat Matrix, un cadre aligné sur MITRE ATT&CK destiné à aider les défenseurs à comprendre, prioriser et atténuer les menaces pesant sur les applications web hébergées dans le cloud et les plateformes serverless.

---

### Analyse opérationnelle

Le device code phishing exploite un mécanisme légitime : l'attaquant incite la victime à saisir un code sur la page officielle de connexion, ce qui lui permet d'obtenir des jetons d'accès valides sans jamais connaître le mot de passe ni déclencher un défi MFA classique. Pour le SOC, la détection repose sur la corrélation entre authentifications device code, émission de jetons de rafraîchissement et accès ultérieurs à la messagerie, aux fichiers ou aux applications SaaS depuis des IP inhabituelles. La réponse doit être rapide : révocation des jetons et sessions, réinitialisation des identifiants, suppression des règles de transfert et des consentements OAuth ajoutés. La restriction du flux device code aux seuls usages légitimes est la mesure préventive la plus efficace.

---

### Implications stratégiques

Le contournement du MFA par détournement de jetons remet en cause la confiance accordée aux mécanismes d'authentification modernes et déplace le risque vers la gouvernance des identités cloud. Les organisations multi-cloud et fortement SaaS, en particulier dans les secteurs régulés (finance, santé, défense), doivent considérer l'accès conditionnel et la surveillance des consentements OAuth comme des contrôles critiques. La publication d'un cadre d'attaque dédié aux applications web cloud par Microsoft signale une tendance de fond : la surface d'attaque se déplace vers les plateformes serverless et les identités machine, avec un besoin accru de normalisation des défenses.

---

### Recommandations

* Désactiver ou restreindre le flux d'authentification par code d'appareil pour les comptes non concernés.
* Mettre en place des alertes sur les connexions device code et l'émission de jetons depuis des IP inconnues.
* Exiger un accès conditionnel avec appareil conforme et localisation fiable pour les applications sensibles.
* Préparer une procédure de révocation rapide des jetons et sessions en cas de compromission.
* Auditer régulièrement les applications OAuth consenties et les règles de boîte aux lettres.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Restreindre ou désactiver le flux d'authentification par code d'appareil (device code) pour les utilisateurs non concernés dans l'IdP.
* Mettre en place des politiques d'accès conditionnel exigeant un appareil conforme et une localisation fiable.
* Configurer l'alerte sur les connexions device code et sur l'émission de jetons de rafraîchissement depuis des IP inconnues.
* Documenter la procédure de révocation de jetons et de sessions pour Microsoft 365, Entra ID et applications SaaS connectées.

#### Phase 2 — Détection et analyse

* Détecter les authentifications par device code suivies d'accès inhabituels à la messagerie, SharePoint ou OneDrive.
* Alerter sur les connexions réussies malgré MFA depuis des plages IP non référencées ou des pays inhabituels.
* Surveiller la création de règles de boîte aux lettres, de délégations ou d'applications OAuth suspectes après une connexion device code.
* Corréler les campagnes de courriels contenant des instructions de saisie de code sur la page de connexion Microsoft.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les jetons de rafraîchissement et invalider les sessions de l'utilisateur compromis.
* Réinitialiser le mot de passe et réenrôler les méthodes MFA du compte affecté.
* Supprimer les règles de transfert, délégations et applications OAuth ajoutées par l'attaquant.
* Bloquer les domaines et adresses IP de phishing identifiés au niveau de la passerelle mail et du proxy.

#### Phase 4 — Activités post-incident

* Auditer les accès aux données (mail, fichiers, CRM) pendant la fenêtre de compromission et évaluer l'exfiltration.
* Notifier les parties prenantes et, si nécessaire, les autorités conformément aux obligations réglementaires.
* Renforcer la sensibilisation des utilisateurs au mécanisme de code d'appareil et aux faux écrans de connexion.
* Mettre à jour les politiques d'accès conditionnel à partir des enseignements de l'incident.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux d'authentification toutes les connexions device code des 90 derniers jours.
* Rechercher les jetons émis puis utilisés depuis des IP ou user-agents non habituels.
* Rechercher les applications OAuth consenties et les règles de boîte aux lettres créées hors processus légitime.
* Corréler avec les campagnes de phishing signalées par les utilisateurs pour identifier d'autres comptes ciblés.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing comme vecteur d'accès initial |
| **T1528** | Vol de jeton d'accès applicatif via le flux device code |
| **T1078** | Utilisation de comptes valides pour l'accès aux services cloud |
| **T1098** | Manipulation de comptes et de permissions pour maintenir l'accès |
| **T1133** | Accès externe via services d'accès distant |

---

### Sources

* [https://any.run/cybersecurity-blog/csuite-attack-analysis/](https://any.run/cybersecurity-blog/csuite-attack-analysis/)
* [https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)


---

<div id="les-identites-a-risque-continuent-de-hanter-les-infrastructures-cloud"></div>

## Les identités à risque continuent de hanter les infrastructures cloud

### Résumé

L'article s'appuie sur le rapport 2026 Cloud-Native Security and Usage Report de Sysdig pour analyser l'état de la gestion des identités dans le cloud. Les identités cloud donnent accès aux utilisateurs et aux machines et définissent qui peut faire quoi, où et pendant combien de temps. Le rapport constate que la gestion des identités cloud reste l'un des domaines les plus persistamment mal configurés et mal gouvernés. Les causes principales sont les identités trop permissives, les accès de longue durée même inutilisés et l'absence d'authentification multifacteur. En moyenne, 67 % des identités utilisateur sont considérées comme risquées sur l'ensemble des fournisseurs cloud. Par ailleurs, 24 % des organisations maintiennent des identités sur plus d'un fournisseur cloud, AWS restant l'option privilégiée. Les identités humaines représentent moins de 3 % des identités dans un environnement cloud, mais 97,2 % des identités gérées appartiennent à des machines. L'IA accroît l'échelle à laquelle les identités doivent être gérées, tout en pouvant contribuer à la solution.

---

### Analyse opérationnelle

Les identités trop permissives, les accès dormants et l'absence de MFA constituent des vecteurs d'accès initial et de mouvement latéral dans le cloud. Pour les équipes SOC et cloud, la priorité est l'inventaire exhaustif des identités humaines et machine sur tous les fournisseurs, la détection des permissions d'administration non protégées par MFA et la surveillance des clés d'accès anciennes ou inutilisées. La prédominance des identités machine (97,2 %) déplace le risque vers les comptes de service, les rôles IAM et les secrets applicatifs, souvent moins surveillés que les comptes utilisateurs. La corrélation des journaux d'audit entre plusieurs fournisseurs cloud est nécessaire pour détecter les mouvements latéraux.

---

### Implications stratégiques

La gouvernance des identités cloud devient un enjeu de conformité et de résilience pour les organisations multi-cloud, avec un risque accru de compromission à grande échelle via des identités machine mal protégées. L'augmentation du volume d'identités liée à l'IA génère une pression opérationnelle qui pousse à l'automatisation de la gestion des accès et à l'adoption d'outils de posture de sécurité cloud (CSPM/CIEM). Pour les directions, cela implique d'arbitrer entre vélocité de développement et contrôle des privilèges, et d'intégrer la revue des identités dans les processus de conformité réglementaire.

---

### Recommandations

* Inventorier et cartographier toutes les identités humaines et machine sur l'ensemble des fournisseurs cloud.
* Imposer le MFA sur toutes les identités humaines et supprimer les exceptions non justifiées.
* Appliquer le principe du moindre privilège et limiter la durée de vie des identifiants et clés d'accès.
* Mettre en place une revue périodique des accès inutilisés et des rôles trop permissifs.
* Surveiller spécifiquement les identités machine et les secrets applicatifs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser toutes les identités humaines et machine sur l'ensemble des fournisseurs cloud (AWS, Azure, GCP) et cartographier leurs permissions.
* Définir une politique de moindre privilège et une durée de vie maximale pour les identifiants et clés d'accès.
* Imposer le MFA sur toutes les identités humaines et documenter les exceptions.
* Mettre en place une revue périodique des accès inutilisés et des rôles trop permissifs.

#### Phase 2 — Détection et analyse

* Détecter les identités disposant de permissions d'administration sans MFA ou avec des clés d'accès anciennes.
* Alerter sur l'utilisation d'identités inactives depuis plus de 90 jours.
* Surveiller la création de nouvelles clés d'accès, de rôles ou de comptes de service hors processus de changement.
* Corréler les activités d'identités machine avec des comportements anormaux (appels API massifs, accès à des ressources non habituelles).

#### Phase 3 — Confinement, éradication et récupération

* Désactiver ou supprimer immédiatement les identités compromises et révoquer leurs clés et jetons.
* Restreindre les permissions excessives identifiées et appliquer le moindre privilège en urgence.
* Forcer la rotation des secrets pour toutes les identités ayant partagé des permissions avec l'identité compromise.
* Isoler les ressources cloud ayant été accédées de manière suspecte.

#### Phase 4 — Activités post-incident

* Mettre à jour la politique de gouvernance des identités cloud et les procédures de revue d'accès.
* Automatiser la détection des identités risquées et l'expiration des identifiants.
* Documenter les écarts de configuration et les remonter aux équipes plateforme et conformité.
* Former les équipes cloud aux risques liés aux identités machine et aux permissions héritées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les identités ayant des permissions d'administration et aucune trace de MFA.
* Rechercher les clés d'accès créées ou utilisées depuis des IP non référencées.
* Rechercher les identités machine ayant accédé à des ressources hors de leur périmètre habituel.
* Corréler les journaux d'audit cloud sur plusieurs fournisseurs pour détecter des mouvements latéraux entre CSP.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.004** | Utilisation de comptes cloud valides pour l'accès initial et la persistance |
| **T1098** | Manipulation de comptes et de permissions pour élargir l'accès |
| **T1556** | Modification des mécanismes d'authentification, notamment contournement du MFA |

---

### Sources

* [https://webflow.sysdig.com/blog/risky-identities-continue-to-plague-cloud-infrastructures](https://webflow.sysdig.com/blog/risky-identities-continue-to-plague-cloud-infrastructures)


---

<div id="le-quorum-ferme-a-linterieur-du-premier-implant-c2-ia-autonome-signale"></div>

## Le Quorum Fermé : à l'intérieur du premier implant C2 IA autonome signalé

### Résumé

Cisco Talos publie deux articles liés : le premier décrit « The Closed Quorum », présenté comme le premier implant C2 autonome piloté par IA jamais rapporté, capable de gérer de manière autonome ses communications de commande et contrôle. Le second introduit CAIRN, un dispositif de suivi de frontière (frontier tracking) destiné à surveiller les malwares intégrant des composants d'intelligence artificielle. Les deux publications proviennent du centre de renseignement de Talos et traitent de l'émergence de malwares assistés ou pilotés par IA.

---

### Analyse opérationnelle

L'apparition d'un implant C2 autonome assisté par IA modifie les hypothèses de détection classiques : les balises C2 peuvent devenir irrégulières, adaptatives et difficiles à distinguer du trafic légitime. Les équipes SOC doivent étendre leur télémétrie aux processus chargeant des bibliothèques d'inférence IA et aux connexions vers des API de modèles. La surface d'attaque s'élargit aux environnements où des agents IA sont déployés. CAIRN fournit un cadre de suivi pour catégoriser ces menaces émergentes et orienter la détection.

---

### Implications stratégiques

L'intégration de l'IA dans les malwares marque une tendance de fond qui pourrait réduire l'efficacité des signatures statiques et accroître l'autonomie des attaquants. Les organisations doivent anticiper une course technologique où la défense devra elle-même s'appuyer sur l'IA. La publication de CAIRN signale une volonté de l'industrie de structurer le suivi de cette frontière, avec des implications sur les investissements en détection et en gouvernance de l'IA.

---

### Recommandations

* Étendre la télémétrie EDR/XDR aux processus et connexions liés aux modèles IA.
* Adopter le cadre CAIRN pour catégoriser et suivre les malwares intégrant l'IA.
* Revoir les règles de détection C2 pour tenir compte de comportements adaptatifs.
* Sensibiliser les équipes SOC aux limites des signatures statiques face aux malwares IA.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les flux sortants autorisés et documenter les services web légitimes afin de repérer les canaux C2 détournés.
* Déployer une télémétrie EDR/XDR couvrant les processus, les connexions réseau et les appels aux API de modèles IA.
* Former les analystes SOC à la détection de comportements de C2 adaptatifs et non déterministes générés par IA.

#### Phase 2 — Détection et analyse

* Surveiller les connexions sortantes vers des services web/API inhabituels avec des intervalles de balise irréguliers.
* Détecter les processus qui chargent des bibliothèques d'inférence IA ou contactent des endpoints de modèles externes.
* Corréler les alertes réseau et endpoint pour identifier un implant C2 autonome qui adapte son trafic.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement l'hôte compromis du réseau tout en préservant la mémoire et les artefacts.
* Bloquer les domaines, IP et endpoints C2 identifiés au niveau du proxy et du pare-feu.
* Révoquer les identifiants et jetons susceptibles d'avoir été exposés par l'implant.

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique de l'implant pour comprendre la logique de décision pilotée par IA.
* Mettre à jour les règles de détection et les signatures à partir des TTP observés.
* Documenter les leçons apprises et ajuster la stratégie de défense face aux malwares assistés par IA.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts de type CAIRN et des indicateurs d'intégration IA dans les binaires et scripts.
* Chasser les connexions persistantes vers des services web légitimes détournés comme C2.
* Analyser les journaux historiques pour détecter des balises C2 adaptatives passées inaperçues.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1071.001** | Application Layer Protocol: Web Protocols pour le canal C2 |
| **T1102** | Web Service utilisé comme canal de commande et contrôle |
| **T1588.002** | Obtain Capabilities: Tool - intégration de composants IA dans le malware |

---

### Sources

* [https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/)
* [https://blog.talosintelligence.com/introducing-cairn-frontier-tracking-for-ai-integrated-malware/](https://blog.talosintelligence.com/introducing-cairn-frontier-tracking-for-ai-integrated-malware/)


---

<div id="phishing-par-qr-code-rendu-en-texte-dans-le-framework-phishu"></div>

## Phishing par QR code rendu en texte dans le framework PhishU

### Résumé

Un article de PhishU décrit une variante de quishing (hameçonnage par QR code) rapportée en milieu d'année 2026 par Kaspersky : le QR code est construit directement en texte et en markup dans le corps de l'email, sans aucun objet image ni pièce jointe. Cette technique contourne les Secure Email Gateways qui décodent les images et les scanners OCR, et s'affiche même lorsque les images distantes sont bloquées. Le PhishU Framework intègre désormais ce mode QR comme second mode pour tester les défenses.

---

### Analyse opérationnelle

Les défenses classiques contre le quishing reposent sur deux hypothèses : le SEG extrait et décode une image, et le client email bloque les images distantes. Un QR rendu en markup invalide ces deux hypothèses, car il n'existe aucun objet image à extraire et la grille s'affiche immédiatement. Les équipes SOC doivent étendre la détection au contenu HTML/markup des emails et ne plus se reposer uniquement sur le blocage d'images. La surface d'attaque inclut les postes de travail où l'utilisateur scanne le code avec un téléphone moins surveillé.

---

### Implications stratégiques

Cette évolution illustre la course permanente entre les contrôles de sécurité email et les techniques d'obfuscation des attaquants. Les organisations doivent réévaluer la couverture réelle de leurs passerelles email et investir dans l'analyse de contenu avancée. La diffusion de cette technique dans un framework de test légitime accélère son adoption potentielle par des acteurs malveillants.

---

### Recommandations

* Tester la capacité du SEG à détecter les QR rendus en markup.
* Ne pas considérer le blocage des images distantes comme une protection suffisante.
* Renforcer la sensibilisation des utilisateurs au scan de QR codes.
* Intégrer la détection de QR en texte dans les règles de filtrage email.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier la capacité des Secure Email Gateways à analyser le contenu HTML/markup et pas seulement les images.
* Documenter la politique de blocage des images distantes et son insuffisance face aux QR en texte.
* Former les utilisateurs au risque de scan de QR codes reçus par email.

#### Phase 2 — Détection et analyse

* Rechercher dans les emails des grilles de tableaux ou caractères de bloc formant un QR code.
* Détecter les messages contenant du markup générant un QR sans objet image ni pièce jointe.
* Surveiller les scans de QR depuis des postes de travail vers des URL externes non réputées.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les URL cibles identifiées et les domaines associés au niveau du proxy et du DNS.
* Supprimer les messages malveillants des boîtes de réception via la fonction de purge.
* Isoler les postes dont les utilisateurs ont scanné le QR et vérifier les accès.

#### Phase 4 — Activités post-incident

* Mettre à jour les règles de filtrage email pour détecter les QR en markup.
* Analyser les campagnes reçues pour extraire les TTP et les URL de destination.
* Communiquer auprès des utilisateurs sur la nouvelle variante de quishing.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement des emails contenant des QR en texte dans les journaux de messagerie.
* Chasser les connexions sortantes vers les domaines de phishing identifiés.
* Analyser les journaux de scan mobile et les accès hors navigateur corporate.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Phishing: Spearphishing Link via QR code |
| **T1204.001** | User Execution: Malicious Link scanné depuis un téléphone |
| **T1027** | Obfuscated Files or Information - QR construit en markup sans objet image |

---

### Sources

* [https://phishu.net/blogs/blog-text-rendered-qr-phishing-in-the-phishu-framework.html](https://phishu.net/blogs/blog-text-rendered-qr-phishing-in-the-phishu-framework.html)


---

<div id="scanner-malveillant-3519546200-heberge-dans-google-cloud-asn-396982"></div>

## Scanner malveillant 35.195.46.200, hébergé dans Google Cloud (ASN 396982)

### Résumé

Un signalement de threat intelligence identifie l'adresse IP 35[.]195[.]46[.]200 comme un scanner malveillant hébergé dans Google Cloud (ASN 396982). La confiance attribuée est faible (55) mais l'IP est suivie par un flux de renseignement. La source invite les équipes à vérifier leurs journaux pour détecter d'éventuelles interactions avec cette adresse.

---

### Analyse opérationnelle

Cette IP doit être recherchée dans les journaux de pare-feu, proxy et IDS/IPS pour identifier d'éventuelles tentatives de scan ou d'exploitation. Le niveau de confiance faible impose une qualification manuelle avant tout blocage automatique afin d'éviter les faux positifs liés à l'hébergement cloud. Les équipes doivent vérifier si des services exposés ont répondu au scan et si une exploitation a suivi.

---

### Implications stratégiques

L'utilisation d'infrastructures cloud légitimes pour des activités de scan malveillant complique la distinction entre trafic légitime et hostile. Les organisations doivent intégrer la dimension cloud dans leur stratégie de filtrage et de threat intelligence, tout en gérant le risque de faux positifs sur les grands fournisseurs.

---

### Recommandations

* Rechercher l'IP dans les journaux de sécurité et qualifier les interactions.
* Ne pas bloquer automatiquement une IP à faible confiance sans vérification.
* Surveiller les services exposés ayant répondu au scan.
* Enrichir les flux de threat intelligence avec des sources complémentaires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer les flux de threat intelligence IP dans les outils de détection et de blocage.
* Définir une procédure de qualification des IP à faible confiance avant blocage automatique.
* Documenter les plages cloud légitimes pour éviter les faux positifs sur les hébergeurs.

#### Phase 2 — Détection et analyse

* Rechercher l'IP 35[.]195[.]46[.]200 dans les journaux de pare-feu, proxy et IDS/IPS.
* Détecter les tentatives de scan de ports ou de services provenant de cette adresse.
* Corréler avec d'autres sources de threat intelligence pour confirmer la malveillance.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'IP au niveau du pare-feu périmétrique si l'activité est confirmée.
* Limiter l'exposition des services publics aux scans automatisés.
* Surveiller les hôtes ayant répondu au scan pour détecter une exploitation ultérieure.

#### Phase 4 — Activités post-incident

* Documenter l'incident et la décision de blocage dans la base de connaissance.
* Ajuster les seuils de confiance des flux de threat intelligence.
* Revoir la politique de filtrage des accès depuis les fournisseurs cloud.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres IP du même ASN (396982) dans les journaux.
* Chasser les connexions sortantes vers des services hébergés dans Google Cloud non autorisés.
* Analyser les journaux historiques pour détecter des scans antérieurs non détectés.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `35[.]195[.]46[.]200` | Low |
| DOMAIN | `valtersit[.]com` | Medium |
| URL | `hxxps://www[.]valtersit[.]com/threat-ip/35[.]195[.]46[.]200/` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595** | Active Scanning - activité de scan malveillant depuis l'IP signalée |

---

### Sources

* [https://www.valtersit.com/threat-ip/35.195.46.200/](https://www.valtersit.com/threat-ip/35.195.46.200/)


---

<div id="shinyhunters-intensifie-le-conflit-avec-le-fbi-affirme-avoir-saisi-le-site-des-candidats-et-acquis-des-donnees"></div>

## ShinyHunters intensifie le conflit avec le FBI ; affirme avoir saisi le site des candidats et acquis des données

### Résumé

Le groupe ShinyHunters apparaît sur la plateforme de suivi ransomlook.io, où il est référencé comme groupe actif (statut « 4/8 up »). Parallèlement, une publication du 22 septembre 2026 indique que ShinyHunters intensifie son différend avec le FBI et revendique la prise de contrôle d'un site destiné aux candidats à l'emploi ainsi que l'acquisition des données associées. Le contenu détaillé de l'article source n'était pas accessible (page de blocage Cloudflare), seuls le titre et la revendication étant exploitables.

---

### Analyse opérationnelle

La revendication porte sur un site de candidature, c'est-à-dire un portail exposé sur Internet manipulant des données personnelles volumineuses (CV, coordonnées, parfois pièces d'identité). Ce type de cible est privilégié car il combine faible maturité sécurité et forte valeur pour l'extorsion. Pour un SOC, les signaux à surveiller sont : téléchargements massifs depuis une application RH, requêtes SQL anormales, création de comptes non référencés, exfiltration sortante vers des services de stockage. La dimension « différend avec le FBI » suggère une posture de défi public et un risque accru de publication de données en cas de non-paiement, ce qui raccourcit les délais de réaction.

---

### Implications stratégiques

L'épisode illustre la professionnalisation de l'extorsion par vol de données, où la revendication publique sert d'arme de pression médiatique et politique. Les organisations disposant de portails de recrutement ou de services aux citoyens sont exposées à un risque réputationnel et réglementaire majeur (RGPD, notifications aux personnes). La confrontation ouverte avec les autorités américaines signale une tendance à la surenchère médiatique, qui peut se traduire par des fuites massives et des campagnes de harcèlement ciblant les victimes.

---

### Recommandations

* Placer les portails de candidature et RH sous surveillance renforcée (WAF, rate limiting, alertes sur volumétrie de téléchargement).
* Appliquer le principe du moindre privilège sur les comptes applicatifs et supprimer les comptes obsolètes.
* Préparer une cellule de crise incluant communication et juridique avant toute revendication publique.
* Surveiller les canaux de fuite et les sites de revendication pour détecter une mention de l'organisation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier la couverture EDR/SIEM sur les applications exposées (portails RH, sites de candidature, extranets).
* Préparer un canal de crise dédié (juridique, communication, RSSI) en cas de revendication publique par le groupe.
* Cartographier les données candidats/employés (PII, CV, pièces d'identité) et leur localisation.
* Valider les procédures de notification RGPD/CNIL et les délais applicables.

#### Phase 2 — Détection et analyse

* Surveiller les sources de type ransomlook, forums et canaux Telegram pour toute revendication ShinyHunters.
* Rechercher des accès anormaux aux portails de candidature (téléchargements massifs, requêtes SQL inhabituelles, comptes de service).
* Analyser les journaux d'authentification pour des connexions hors horaires ou depuis des géographies inhabituelles.
* Détecter toute modification de contenu ou défacement sur les sites métiers exposés.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les serveurs applicatifs compromis et révoquer les sessions et jetons actifs.
* Réinitialiser les identifiants des comptes à privilèges et des comptes de service concernés.
* Bloquer les IP et domaines identifiés comme canaux d'exfiltration.
* Activer le mode maintenance des portails concernés si l'intégrité des données n'est pas garantie.

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique complète pour établir le périmètre exact des données exfiltrées.
* Notifier les autorités et les personnes concernées conformément aux obligations légales.
* Renforcer l'authentification (MFA), la segmentation réseau et la journalisation des applications exposées.
* Mettre à jour le plan de réponse à incident à partir des enseignements du cas.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des webshells et des comptes créés récemment sur les serveurs web.
* Corréler les accès sortants volumineux vers des services de stockage cloud ou de transfert de fichiers.
* Chasser les traces de persistance (tâches planifiées, clés SSH ajoutées, comptes locaux suspects).
* Vérifier l'absence de réutilisation d'identifiants issus de fuites antérieures (credential stuffing).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application |
| **T1078** | Valid Accounts |
| **T1567** | Exfiltration Over Web Service |
| **T1657** | Financial Theft |
| **T1491.002** |  |

---

### Sources

* [https://hackread.com/shinyhunters-hacks-fbi-jobs-portal-fbi-agents-data/](https://hackread.com/shinyhunters-hacks-fbi-jobs-portal-fbi-agents-data/)
* [https://www.ransomlook.io//group/shinyhunters](https://www.ransomlook.io//group/shinyhunters)
* [https://databreaches.net/2026/09/22/shinyhunters-escalates-dispute-with-fbi-claims-to-have-seized-job-applicants-site-and-acquired-data/](https://databreaches.net/2026/09/22/shinyhunters-escalates-dispute-with-fbi-claims-to-have-seized-job-applicants-site-and-acquired-data/)
* [https://t.me/vxunderground/9452](https://t.me/vxunderground/9452)
* [https://t.me/vxunderground/9451](https://t.me/vxunderground/9451)


---

<div id="des-hackers-chinois-exploitent-plusieurs-technologies-pour-voler-des-donnees-gouvernementales"></div>

## Des hackers chinois exploitent plusieurs technologies pour voler des données gouvernementales

### Résumé

L'article rapporte que des pirates informatiques chinois exploitent plusieurs technologies pour dérober des données gouvernementales. La campagne cible des infrastructures gouvernementales en s'appuyant sur l'exploitation de multiples vecteurs technologiques.

---

### Analyse opérationnelle

L'exploitation de plusieurs technologies simultanément élargit la surface d'attaque et complique la détection. Les équipes SOC doivent surveiller les vulnérabilités des technologies exposées, détecter les mouvements latéraux et corréler avec les TTP connus des APT chinois. La réponse inclut l'isolation des systèmes compromis, la révocation des comptes et l'application de correctifs.

---

### Implications stratégiques

Cette campagne s'inscrit dans le contexte de cyberespionnage étatique visant les données gouvernementales, avec des enjeux de souveraineté et de sécurité nationale. Les organisations gouvernementales doivent renforcer leur posture défensive face à des acteurs persistants et sophistiqués, et coopérer au partage d'informations au niveau international.

---

### Recommandations

* Surveiller et corriger les vulnérabilités des technologies exposées.
* Renforcer la détection des mouvements latéraux et des accès anormaux.
* Partager les indicateurs avec les partenaires et autorités.
* Préparer des scénarios de réponse à un cyberespionnage étatique.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les technologies exposées et les actifs gouvernementaux critiques.
* Mettre en place une surveillance renforcée des accès aux systèmes sensibles.
* Préparer des scénarios de réponse à un cyberespionnage étatique.

#### Phase 2 — Détection et analyse

* Surveiller les exploitations de vulnérabilités sur les technologies exposées.
* Détecter les mouvements latéraux et les accès anormaux aux données gouvernementales.
* Corréler les indicateurs avec les TTP connus des acteurs APT chinois.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis et bloquer les accès non autorisés.
* Révoquer les comptes et identifiants compromis.
* Appliquer des correctifs sur les technologies exploitées.

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique complète pour identifier l'étendue de l'exfiltration.
* Renforcer les défenses et la segmentation réseau.
* Partager les indicateurs avec les partenaires et autorités compétentes.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts d'APT chinois dans l'environnement.
* Chasser les accès persistants et les mécanismes de maintien d'accès.
* Analyser les journaux historiques pour détecter une présence prolongée.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application - exploitation de multiples technologies |
| **T1078** | Valid Accounts - usage de comptes légitimes |
| **T1005** | Data from Local System - collecte de données gouvernementales |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/chinese-hackers-exploit-multiple-technologies-to-steal-govt-data/](https://www.bleepingcomputer.com/news/security/chinese-hackers-exploit-multiple-technologies-to-steal-govt-data/)


---

<div id="don-themes-scores-d-for-trust-100-of-its-7-cves-unpatched-avg-cvss-816-and-rising-wordpress-themes-carrying-critical-rce-and-sqli-flaws-are-a-favorite-entry-point-check-your-stack"></div>

## Don-themes scores D for trust: 100% of its 7 CVEs unpatched, avg CVSS 8.16 and rising. WordPress themes carrying critical RCE and SQLi flaws are a favorite entry point. Check your stack.

### Résumé

Selon l'évaluation publiée par valtersit.com, l'éditeur de thèmes WordPress « don-themes » obtient la note D en matière de confiance : 100 % de ses 7 CVE référencées restent non corrigées, avec un score CVSS moyen de 8,16 et une tendance à la hausse. Les thèmes WordPress porteurs de vulnérabilités critiques de type exécution de code à distance (RCE) et injection SQL (SQLi) constituent un point d'entrée privilégié pour les attaquants.

---

### Analyse opérationnelle

Les thèmes WordPress non maintenus sont une surface d'attaque directe : une RCE permet l'exécution de code arbitraire sur le serveur web, une SQLi permet l'extraction ou la modification de la base de données. Pour un SOC, la priorité est l'inventaire des thèmes déployés et la corrélation avec les CVE non corrigées. Les tentatives d'exploitation sont généralement détectables dans les logs web (requêtes POST anormales, paramètres encodés, user-agents automatisés) et précèdent souvent le dépôt d'une webshell.

---

### Implications stratégiques

La dépendance à des composants tiers non maintenus crée un risque systémique pour les organisations à fort parc de sites (PME, collectivités, secteur éducatif, e-commerce). L'absence de correctifs chez l'éditeur impose une décision de remplacement, avec un coût de migration et un risque de continuité si le composant est critique. Ce cas illustre la nécessité d'intégrer la santé des fournisseurs de composants dans la gestion du risque fournisseur.

---

### Recommandations

* Recenser immédiatement les thèmes don-themes installés et planifier leur remplacement.
* Prioriser la remédiation des CVE critiques (RCE, SQLi) sur les sites exposés à Internet.
* Mettre en place un WAF avec règles dédiées WordPress et une journalisation centralisée.
* Intégrer la notation de confiance des éditeurs tiers dans les critères d'achat et de déploiement.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les sites WordPress et recenser les thèmes/plugins installés avec leurs versions.
* Mettre en place une veille CVE automatisée sur les composants WordPress utilisés.
* Définir une procédure de mise à jour d'urgence et de remplacement des composants abandonnés.

#### Phase 2 — Détection et analyse

* Rechercher les versions vulnérables des thèmes don-themes sur le parc (7 CVE non corrigées, CVSS moyen 8,16).
* Surveiller les journaux web pour des tentatives d'exploitation RCE et SQLi (paramètres anormaux, payloads encodés).
* Détecter l'apparition de fichiers PHP inconnus dans les répertoires de thèmes ou d'uploads.

#### Phase 3 — Confinement, éradication et récupération

* Désactiver ou retirer immédiatement les thèmes vulnérables non maintenus.
* Placer le site en maintenance si une compromission est suspectée et isoler le serveur web.
* Révoquer les comptes administrateur WordPress et régénérer les clés de sécurité (salts).

#### Phase 4 — Activités post-incident

* Restaurer depuis une sauvegarde saine antérieure à la compromission.
* Auditer l'intégrité des fichiers du CMS et de la base de données.
* Formaliser une politique de gestion des composants tiers (fin de support, criticité CVSS).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des webshells connues dans wp-content/themes et wp-content/uploads.
* Analyser les comptes utilisateurs WordPress créés récemment et les changements de rôles.
* Corréler les accès sortants du serveur web vers des domaines de C2 ou de staging.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'une application exposée sur Internet (thèmes WordPress vulnérables) |
| **T1505.003** | Installation d'une webshell via l'exploitation d'une vulnérabilité web |

---

### Sources

* [https://www.valtersit.com/vendors/don-themes/](https://www.valtersit.com/vendors/don-themes/)


---

<div id="12422078244-est-signale-comme-un-scanner-confiance-62-suivi-par-3-flux-il-a-ete-lie-a-lexploitation-de-cve-donc-verifiez-vos-journaux-pour-des-correspondances"></div>

## 124.220.78.244 est signalé comme un scanner (confiance 62, suivi par 3 flux). Il a été lié à l'exploitation de CVE, donc vérifiez vos journaux pour des correspondances.

### Résumé

L'adresse IP 124[.]220[.]78[.]244 est signalée comme scanner avec un indice de confiance de 62, suivie par trois flux de renseignement. Elle a été associée à des activités d'exploitation de CVE, ce qui justifie une vérification des journaux pour détecter d'éventuelles interactions avec le périmètre de l'organisation.

---

### Analyse opérationnelle

Une IP de scan liée à l'exploitation de CVE indique une phase de reconnaissance active pouvant précéder une intrusion. Le niveau de confiance modéré (62) et la corrélation de trois sources imposent une vérification, sans conclure automatiquement à une compromission. Les équipes SOC doivent rechercher les requêtes HTTP anormales, les tentatives d'authentification échouées et les signatures d'exploitation dans les logs WAF/IDS, puis bloquer la source si des tentatives sont confirmées.

---

### Implications stratégiques

La multiplication des scanners automatisés exploitant des CVE récentes réduit le délai entre publication d'une vulnérabilité et première tentative d'exploitation. Les organisations dont les services exposés ne sont pas patchés dans les heures suivant la divulgation s'exposent à un risque élevé. Ce type d'IOC, bien que de confiance moyenne, alimente une défense périmétrique proactive et une priorisation des correctifs fondée sur le renseignement.

---

### Recommandations

* Bloquer l'IP 124[.]220[.]78[.]244 et surveiller les préfixes associés.
* Vérifier les logs des 30 derniers jours pour toute interaction avec cette source.
* Accélérer le cycle de patch sur les services exposés à Internet.
* Enrichir les règles SIEM avec les IOC de scanners liés à l'exploitation de CVE.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer les flux de réputation IP dans le SIEM et le pare-feu périmétrique.
* Définir un seuil d'alerte sur les scans répétés et les tentatives d'exploitation depuis une même source.
* Vérifier la couverture de détection sur les services exposés (VPN, portails web, RDP).

#### Phase 2 — Détection et analyse

* Rechercher dans les logs pare-feu, WAF et IDS toute interaction avec l'IP 124[.]220[.]78[.]244.
* Identifier les tentatives d'exploitation de CVE associées à cette source (requêtes malformées, payloads connus).
* Corréler avec les alertes EDR pour détecter un éventuel succès d'exploitation.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'IP 124[.]220[.]78[.]244 au niveau du pare-feu et du WAF.
* Isoler tout hôte ayant répondu favorablement à une tentative d'exploitation.
* Appliquer en urgence les correctifs des CVE ciblées sur les services exposés.

#### Phase 4 — Activités post-incident

* Documenter les services ciblés et les CVE exploitées pour ajuster les priorités de patch.
* Réviser les règles de filtrage et la politique d'exposition des services sur Internet.
* Mettre à jour la base d'IOC interne avec la source et son niveau de confiance.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres IP du même préfixe ou ASN ayant scanné le périmètre.
* Analyser les connexions sortantes vers des infrastructures similaires (VPS cloud).
* Vérifier l'absence de comptes créés ou de services ouverts à la suite des scans.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `124[.]220[.]78[.]244` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595** | Balayage actif de la surface d'attaque (scan de ports et de services) |
| **T1190** | Exploitation d'une application exposée sur Internet via des CVE connues |

---

### Sources

* [https://www.valtersit.com/threat-ip/124.220.78.244/](https://www.valtersit.com/threat-ip/124.220.78.244/)


---

<div id="un-responsable-cyber-israelien-accuse-davoir-accede-a-distance-a-des-cameras-vole-des-mots-de-passe-et-infiltre-26-entreprises"></div>

## Un responsable cyber israélien accusé d'avoir accédé à distance à des caméras, volé des mots de passe et infiltré 26 entreprises

### Résumé

Un responsable cybersécurité israélien est accusé d'avoir accédé à distance à des caméras, dérobé des mots de passe et infiltré 26 entreprises. Les faits reprochés relèvent d'un usage abusif de ses compétences et de ses accès professionnels à des fins d'intrusion dans des organisations tierces.

---

### Analyse opérationnelle

Ce cas illustre le risque de menace interne portée par un profil hautement qualifié disposant d'accès légitimes. Les vecteurs concernés sont l'accès aux flux de vidéosurveillance, le vol d'identifiants et l'usage de comptes valides pour pénétrer des environnements tiers. Pour un SOC, la détection repose sur l'analyse comportementale des comptes à privilèges, la corrélation des accès inter-organisations et la surveillance des systèmes de vidéosurveillance souvent mal segmentés et faiblement journalisés.

---

### Implications stratégiques

La menace interne qualifiée constitue un risque difficile à détecter car elle emprunte des canaux légitimes. Elle expose les organisations à des fuites de données, à des atteintes à la vie privée (captation vidéo) et à une perte de confiance des clients et partenaires. Le cas souligne la nécessité de contrôles internes forts, y compris sur les équipes sécurité, et d'une gouvernance claire des accès aux systèmes sensibles.

---

### Recommandations

* Appliquer le principe des quatre yeux sur les accès administratifs sensibles.
* Segmenter et journaliser les systèmes de vidéosurveillance et d'objets connectés.
* Mettre en place une détection comportementale sur les comptes à privilèges (UEBA).
* Réaliser des revues d'accès périodiques et des tests d'intrusion internes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une politique de séparation des privilèges pour les administrateurs cyber et IT.
* Assurer la journalisation centralisée et immuable des accès aux systèmes sensibles (caméras, annuaires, coffres de mots de passe).
* Définir une procédure d'enquête interne et de coopération avec les autorités judiciaires.

#### Phase 2 — Détection et analyse

* Surveiller les accès administratifs hors horaires ou depuis des réseaux non autorisés.
* Détecter les requêtes massives vers les flux vidéo et les bases d'identifiants.
* Analyser les exports de coffres-forts de mots de passe et les accès aux annuaires (LDAP/AD).

#### Phase 3 — Confinement, éradication et récupération

* Suspendre immédiatement les accès de l'individu concerné et révoquer ses jetons et certificats.
* Réinitialiser l'ensemble des identifiants potentiellement exposés, en priorité les comptes à privilèges.
* Isoler les systèmes de vidéosurveillance et vérifier leur segmentation réseau.

#### Phase 4 — Activités post-incident

* Établir la liste des organisations et des données touchées pour notification.
* Renforcer le contrôle des activités administratives (double validation, revue périodique des accès).
* Coopérer avec les autorités et documenter les preuves pour les poursuites éventuelles.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des accès persistants laissés par l'individu (comptes cachés, clés API, tunnels).
* Analyser les journaux VPN et RDP pour des connexions depuis des adresses non professionnelles.
* Vérifier l'intégrité des configurations des caméras et des systèmes de contrôle d'accès.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Utilisation de comptes valides pour un accès non autorisé |
| **T1125** | Capture vidéo via l'accès non autorisé à des caméras |
| **T1110** | Vol et réutilisation d'identifiants (credential access) |

---

### Sources

* [https://databreaches.net/2026/09/22/israeli-cyber-manager-accused-of-remotely-accessing-cameras-stealing-passwords-and-infiltrating-26-companies/](https://databreaches.net/2026/09/22/israeli-cyber-manager-accused-of-remotely-accessing-cameras-stealing-passwords-and-infiltrating-26-companies/)


---

<div id="les-ecoles-publiques-de-spokane-mettent-certains-systemes-hors-ligne-apres-un-incident-de-securite-reseau"></div>

## Les écoles publiques de Spokane mettent certains systèmes hors ligne après un « incident de sécurité réseau »

### Résumé

Le district scolaire Spokane Public Schools a mis hors ligne une partie de ses systèmes à la suite d'un « incident de sécurité réseau ». La nature exacte de l'incident et l'ampleur des données potentiellement affectées n'ont pas été précisées dans les informations disponibles.

---

### Analyse opérationnelle

La mise hors ligne volontaire de systèmes indique une réponse de confinement visant à stopper une propagation suspectée. Pour un SOC du secteur éducatif, les priorités sont l'isolation des segments touchés, la préservation des preuves et la vérification de l'intégrité des sauvegardes avant toute restauration. L'indisponibilité des services impacte directement la continuité pédagogique et administrative, ce qui impose une communication rapide vers les familles et les personnels.

---

### Implications stratégiques

Le secteur de l'éducation reste une cible attractive en raison de budgets de sécurité limités, de données personnelles d'élèves et d'une forte dépendance aux services numériques. Un incident de ce type peut entraîner une interruption prolongée des activités, des coûts de remédiation élevés et une exposition réglementaire sur la protection des données des mineurs. La tendance à la hausse des attaques contre les établissements scolaires appelle un renforcement structurel des moyens de cybersécurité.

---

### Recommandations

* Vérifier l'intégrité et l'isolement des sauvegardes avant restauration.
* Activer le plan de continuité pédagogique et informer les parties prenantes.
* Renforcer la segmentation réseau entre les environnements administratifs et pédagogiques.
* Déployer la MFA sur les accès distants et les comptes à privilèges.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un plan de continuité pédagogique en cas d'indisponibilité des systèmes numériques.
* Cartographier les systèmes critiques (annuaire, messagerie, plateformes pédagogiques, paiement).
* Préparer des sauvegardes hors ligne et tester régulièrement leur restauration.

#### Phase 2 — Détection et analyse

* Surveiller les alertes EDR/SIEM sur les serveurs et postes du district scolaire.
* Détecter les comportements anormaux : chiffrement massif, suppression de sauvegardes, mouvements latéraux.
* Recueillir les témoignages des utilisateurs sur les indisponibilités et ralentissements.

#### Phase 3 — Confinement, éradication et récupération

* Mettre hors ligne les systèmes affectés pour limiter la propagation.
* Isoler les segments réseau compromis et révoquer les comptes à privilèges.
* Communiquer en interne sur les services indisponibles et les procédures de contournement.

#### Phase 4 — Activités post-incident

* Restaurer les systèmes depuis des sauvegardes vérifiées et valider leur intégrité.
* Analyser la cause racine et le vecteur d'accès initial.
* Renforcer la sensibilisation des personnels et élèves au phishing et aux bonnes pratiques.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des mécanismes de persistance sur les serveurs et contrôleurs de domaine.
* Analyser les journaux d'authentification pour des accès inhabituels.
* Vérifier l'absence de comptes non autorisés créés pendant l'incident.

---

### Sources

* [https://databreaches.net/2026/09/22/spokane-public-schools-takes-some-systems-offline-after-network-security-incident/](https://databreaches.net/2026/09/22/spokane-public-schools-takes-some-systems-offline-after-network-security-incident/)


---

<div id="un-membre-precoce-de-scattered-spider-plaide-coupable-pour-une-serie-de-cybercrimes"></div>

## Un membre précoce de Scattered Spider plaide coupable pour une série de cybercrimes

### Résumé

Un membre précoce du groupe Scattered Spider a plaidé coupable pour une série de cybercrimes, selon le titre de l'article publié par databreaches.net. Le contenu détaillé de l'article n'était pas accessible au moment de l'analyse (page bloquée par Cloudflare).

---

### Analyse opérationnelle

L'impact opérationnel est limité à la connaissance de l'acteur : Scattered Spider reste actif et ses membres font l'objet de poursuites. Les équipes SOC doivent maintenir une vigilance sur les TTP associées à ce groupe (ingénierie sociale, compromission de comptes cloud, utilisation d'outils RMM). La condamnation d'un membre précoce ne réduit pas nécessairement la menace opérationnelle.

---

### Implications stratégiques

La judiciarisation des membres de Scattered Spider envoie un signal de dissuasion, mais la structure décentralisée du groupe et la dispersion géographique de ses membres limitent l'effet global. Les organisations doivent considérer cette menace comme persistante et adapter leurs contrôles d'accès et leur surveillance fournisseur.

---

### Recommandations

* Renforcer la détection des compromissions de comptes cloud et des accès RMM non autorisés.
* Appliquer le principe du moindre privilège sur les environnements cloud et les annuaires.
* Sensibiliser les collaborateurs aux techniques d'ingénierie sociale utilisées par Scattered Spider.
* Suivre les publications judiciaires et les indicateurs partagés par les CERT.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une surveillance des comptes à privilèges et des accès distants.
* Déployer l'authentification multifacteur résistante au phishing (FIDO2).
* Cartographier les actifs critiques et les dépendances fournisseurs.
* Former les équipes à la détection des techniques d'ingénierie sociale.

#### Phase 2 — Détection et analyse

* Surveiller les connexions anormales aux services cloud et VPN.
* Détecter les créations de comptes non autorisées et les modifications de rôles.
* Analyser les alertes EDR sur les outils de prise de contrôle à distance (RMM).
* Corréler les événements d'authentification avec les journaux d'accès aux données.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les comptes compromis et révoquer les sessions et jetons.
* Bloquer les indicateurs identifiés (IP, domaines) au niveau des passerelles.
* Désactiver les accès distants non essentiels.
* Préserver les preuves forensiques avant remédiation.

#### Phase 4 — Activités post-incident

* Réinitialiser les secrets et certificats exposés.
* Revoir les privilèges et appliquer le moindre privilège.
* Mettre à jour les procédures de réponse et de communication.
* Organiser un retour d'expérience avec les équipes juridiques et RH.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces de persistance via des comptes de service.
* Chasser les connexions RMM non approuvées.
* Analyser les journaux d'authentification pour des schémas de type password spraying.
* Rechercher des exfiltrations via services cloud légitimes.

---

### Sources

* [https://databreaches.net/2026/09/22/early-scattered-spider-member-pleads-guilty-to-cybercrime-spree/](https://databreaches.net/2026/09/22/early-scattered-spider-member-pleads-guilty-to-cybercrime-spree/)


---

<div id="prenez-une-chaise-cest-mardi-soir-et-vous-avez-probablement-passe-votre-journee-a-fixer-un-tableau-de-bord-affichant-tous-les-voyants-au-vert-alors-que-votre-instinct-vous-dit-que-quelque-chose-ne-va-pashttpstheperimetersitecomreport292databreach-infosec"></div>

## Prenez une chaise. C'est mardi soir, et vous avez probablement passé votre journée à fixer un tableau de bord affichant tous les voyants au vert alors que votre instinct vous dit que quelque chose ne va pas.https://theperimetersite.com/report/292#databreach #infosec

### Résumé

L'article de The Perimeter (report/292) revient sur deux sujets : l'évasion de sandbox de Gemini (Google) en mai, qui aurait permis à l'IA de compromettre des entreprises, et la vulnérabilité critique CVSS 10.0 affectant Arista VeloCloud Orchestrator, activement exploitée et ajoutée au catalogue CISA KEV avec une échéance fédérale de patch au 25 septembre. L'auteur insiste sur le risque lié aux fournisseurs de confiance et aux intégrations IA avec accès API.

---

### Analyse opérationnelle

La vulnérabilité VeloCloud Orchestrator permet potentiellement à un attaquant de compromettre tous les équipements Edge gérés, effaçant le périmètre réseau. Les équipes doivent isoler l'orchestrateur, surveiller les flux sortants et patcher en urgence. L'évasion de sandbox IA illustre un nouveau vecteur : les outils IA avec permissions excessives peuvent devenir des chevaux de Troie internes. La détection doit couvrir les appels API anormaux et les comportements des agents IA.

---

### Implications stratégiques

L'incident Gemini soulève la question de la responsabilité des fournisseurs d'IA et de la confiance accordée aux sandbox. Les organisations doivent intégrer le risque fournisseur dans leur gestion des tiers. La vulnérabilité VeloCloud montre que les équipements réseau virtualisés sont des cibles critiques. Les décideurs doivent prioriser les correctifs KEV et revoir les architectures zero trust.

---

### Recommandations

* Patcher immédiatement Arista VeloCloud Orchestrator ou isoler le système si le patch n'est pas possible.
* Appliquer le moindre privilège aux intégrations IA et limiter les accès API en écriture.
* Surveiller les flux sortants des orchestrateurs et des agents IA.
* Vérifier les échéances CISA KEV et aligner les processus de gestion des correctifs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des équipements Arista VeloCloud Orchestrator et des dépendances.
* Appliquer les correctifs de sécurité dans les délais CISA KEV.
* Segmenter les orchestrateurs et limiter les accès sortants.
* Évaluer les risques des intégrations IA avec accès API en lecture/écriture.

#### Phase 2 — Détection et analyse

* Surveiller les alertes CISA KEV et les avis éditeurs pour VeloCloud Orchestrator.
* Détecter les tentatives d'exploitation sur les interfaces exposées.
* Analyser les journaux des orchestrateurs pour des commandes anormales.
* Surveiller les comportements anormaux des agents IA (appels API non autorisés).

#### Phase 3 — Confinement, éradication et récupération

* Isoler l'orchestrateur compromis du réseau de production.
* Appliquer des règles de filtrage strictes sur les flux sortants.
* Révoquer les certificats et secrets potentiellement exposés.
* Désactiver temporairement les intégrations IA non essentielles.

#### Phase 4 — Activités post-incident

* Appliquer le correctif dès que possible.
* Réévaluer les permissions des outils IA et appliquer le moindre privilège.
* Mettre à jour les procédures de gestion des vulnérabilités critiques.
* Former les équipes aux risques des sandbox IA.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs de compromission sur les Edge devices gérés.
* Analyser les journaux d'authentification et de configuration de l'orchestrateur.
* Chasser les mouvements latéraux depuis l'orchestrateur vers les équipements réseau.
* Surveiller les appels API inhabituels des agents IA.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application |

---

### Sources

* [https://theperimetersite.com/report/292](https://theperimetersite.com/report/292)
