# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Alerte FBI/IC3 : le groupe cybercriminel TeamPCP](#alerte-fbiic3-le-groupe-cybercriminel-teampcp)
  * [Saisie FBI du domaine netnut[.]com lié au botnet POPA](#saisie-fbi-du-domaine-netnutcom-lie-au-botnet-popa)
  * [Compromise Assessments 2025 : angles morts, LoLBins et détection proactive](#compromise-assessments-2025-angles-morts-lolbins-et-detection-proactive)
  * [Panneau d'affiliation ciblant Microsoft 365 et campagne de phishing SlidesGo→Wix](#panneau-daffiliation-ciblant-microsoft-365-et-campagne-de-phishing-slidesgowix)
  * [Possible campagne de phishing utilisant SlidesGo comme redirecteur vers un site Wix](#possible-campagne-de-phishing-utilisant-slidesgo-comme-redirecteur-vers-un-site-wix)
  * [Rapport de tendances des techniques d'attaque Q2 2026 (AhnLab ASEC)](#rapport-de-tendances-des-techniques-dattaque-q2-2026-ahnlab-asec)
  * [Catan and Mouse (Cisco Talos Intelligence)](#catan-and-mouse-cisco-talos-intelligence)
  * [ShinyHunters revendique le vol de plus de 40 Go de données à l'Université de Nottingham](#shinyhunters-revendique-le-vol-de-plus-de-40-go-de-donnees-a-luniversite-de-nottingham)
  * [Vague de revendications ransomware LockBit, Akira et TheGentlemen ciblant la tech, le gouvernement et l'industrie](#vague-de-revendications-ransomware-lockbit-akira-et-thegentlemen-ciblant-la-tech-le-gouvernement-et-lindustrie)
  * [Un eurodéputé chargé d'enquêter sur Pegasus lui-même visé par le logiciel espion](#un-eurodepute-charge-denqueter-sur-pegasus-lui-meme-vise-par-le-logiciel-espion)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le volume de vulnérabilités demeure exceptionnellement élevé avec 41 signalements, signalant une intensification des divulgations techniques qui exige une priorisation immédiate des correctifs sur les actifs exposés, en particulier pour les CVE critiques affectant les solutions largement déployées. Côté régulatoire, les 6 annonces traduisent une accélération normative cohérente avec les dynamiques européennes (DORA, NIS2) et américaines, imposant aux organisations une veille conformité proactive. La pression géopolitique reste marquée (4 événements),維持 un climat de risque cyber élevé lié aux tensions étatiques et aux opérations d'influence, tandis que les 2 compromissions de données recensées confirment la persistance du vol massif d'identifiants et de données clients, principale cible des acteurs threat observés. Les 2 activités de threat actors, conjuguées au volume de vulnérabilités, suggèrent une exploitation opportuniste rapide des failles nouvellement publiées.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **TeamPCP** | finance | Fraude financière, opérations d'escroquerie organisées |  | [https://www.ic3.gov/CSA/2026/260702.pdf](https://www.ic3.gov/CSA/2026/260702.pdf) |
| **ShinyHunters** | éducation, multi_secteurs | Exfiltration de bases de données, publication/revente sur darkweb et extorsion | T1567, T1657 | [https://www.yazoul.net/intel/claim/2026-06-10-university-of-nottingham-hit-by-shinyhunters-june-2026](https://www.yazoul.net/intel/claim/2026-06-10-university-of-nottingham-hit-by-shinyhunters-june-2026) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Moyen-Orient, Syrie, Liban, Iran** | Gouvernement/Politique | Transition post-conflit et reconstruction en Syrie après la chute du régime Assad | Plus de quinze ans après le début de la guerre civile et la chute du régime Assad fin 2024, la Syrie reste confrontée à de nombreux enjeux politiques, sécuritaires, économiques et sociaux. Les attaques israélo-américaines contre l'Iran et le Liban (à partir du 28 février) ont déstabilisé l'ensemble de la région et retardé les investissements directs étrangers (IDE) indispensables à la reconstruction du pays. Les principaux appuis potentiels montrent leurs limites : la Turquie en raison de ses difficultés économiques intérieures, l'Arabie saoudite dont les projets de MBS sont entravés par les conséquences du 28 février. L'Union européenne reste spectatrice, davantage préoccupée par le retour des réfugiés syriens que par un plan d'aide effectif. La Chine se montre prudente et la Russie, affaiblie par la guerre en Ukraine, n'est plus un acteur influent bien qu'elle ait pérennisé ses bases militaires. Les élections législatives d'octobre 2025 ont marqué un tournant politique mais soulèvent des interrogations sur la capacité des autorités à renforcer la souveraineté, reconstruire des institutions solides et une société civile active. La situation sécuritaire s'est améliorée depuis les violences de mars 2025 mais reste fragile. Donald Trump aurait proposé que les troupes d'Ahmed al-Charaa interviennent militairement au Liban contre le Hezbollah, témoignant d'une méconnaissance des dynamiques régionales. | [https://www.iris-france.org/syrie-une-transition-en-question/](https://www.iris-france.org/syrie-une-transition-en-question/) |
| **France, Europe, États-Unis, Russie, Chine** | Gouvernement/Politique | Vision géopolitique de Jean-Luc Mélenchon pour la présidentielle 2027 | Lors d'un colloque de l'Institut La Boétie le 27 juin, Jean-Luc Mélenchon a présenté une vision de « révolution géopolitique ». Son analyse repose sur l'indissociabilité de l'ordre économique et de l'ordre géopolitique : depuis 1971, les États-Unis bénéficient du privilège d'émission monétaire en dollars, adossé notamment au pétrole, dans un contexte de crise écologique. Il estime que Washington n'a pas anticipé le rapprochement sino-russe ni la montée en puissance de la Chine. Il dresse un parallèle avec l'effondrement de l'URSS après son retrait d'Afghanistan et suggère qu'un scénario comparable pourrait toucher les États-Unis. Il défend un monde organisé autour du droit international et de l'ONU (réformée), une sortie de l'OTAN, l'ouverture de discussions avec la Russie sur des garanties de sécurité mutuelles après le retrait d'Ukraine, un désarmement nucléaire au Moyen-Orient et un rapprochement coopératif avec la Chine. | [https://www.iris-france.org/melenchon-veut-une-revolution-geopolitique/](https://www.iris-france.org/melenchon-veut-une-revolution-geopolitique/) |
| **Asie-Pacifique, Corée du Sud, France, États-Unis** | Défense/Industrie navale nucléaire | Coopération franco-coréenne pour le programme de sous-marin à propulsion nucléaire sud-coréen | Le programme de sous-marin à propulsion nucléaire (SNA) sud-coréen est entré en phase concrète : le 26 mai 2026, le ministère sud-coréen de la Défense a publié le « Plan de base pour le développement du SNA de la République de Corée », précisant l'usage d'uranium faiblement enrichi (LEU) à moins de 20 %, le développement et la construction réalisés en Corée du Sud, et le respect des engagements de non-prolifération et des garanties de l'AIEA. La Corée du Sud doit faire de l'accord LEU avec les États-Unis l'axe fondamental du programme tout en institutionnalisant une coopération avec la France dans les domaines non nucléaires : intégration navale, revue de sûreté de conception, maintenance, formation, installation d'essais à terre et culture de sûreté nucléaire. L'approche est explicitement complémentaire à l'alliance américaine et vise à combiner l'expérience américaine des réacteurs à HEU et l'expérience française de la propulsion nucléaire au LEU pour renforcer les chances de succès et la sûreté. | [https://www.iris-france.org/cooperation-franco-coreenne-pour-la-construction-du-sous-marin-a-propulsion-nucleaire-sna-sud-coreen/](https://www.iris-france.org/cooperation-franco-coreenne-pour-la-construction-du-sous-marin-a-propulsion-nucleaire-sna-sud-coreen/) |
| **France, Europe, États-Unis** | Technologies de l'information / Intelligence artificielle | Souveraineté numérique et dépendance aux acteurs américains de l'IA | Longtemps marginalisée, la thématique de la souveraineté numérique est revenue au premier plan du débat politique français après deux événements récents : le ralliement politique de la Silicon Valley à Donald Trump, et la décision d'Anthropic (le 12 juin) de couper temporairement l'accès de ses modèles d'IA les plus puissants aux « ressortissants étrangers », notamment européens. Le sujet fait l'objet d'un consensus théorique inhabituel à travers la classe politique française : Jean-Luc Mélenchon (évoquant sur X « l'urgence d'être indépendants et souverains »), Jordan Bardella (« l'IA est déjà un sujet de souveraineté nationale majeur ») et Gabriel Attal (risque d'une « vassalisation totale de la France »). Toutefois, la définition opérationnelle de la souveraineté numérique reste floue dans un monde interconnecté où une PME française peut utiliser un logiciel américain stockant ses données sur un serveur en Allemagne analysées par un prestataire en Inde. La question se pose : faut-il n'utiliser que des logiciels et serveurs français ? Européens ? | [https://www.lemonde.fr/pixels/article/2026/07/03/numerique-pour-etre-souverains-il-faut-surtout-etre-libres_6718446_4408996.html](https://www.lemonde.fr/pixels/article/2026/07/03/numerique-pour-etre-souverains-il-faut-surtout-etre-libres_6718446_4408996.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| CELEX:52025AE4332 – JOIN(2025) 27 final | Comité économique et social européen (CESE) / Commission européenne | 2026-07-02 | Union européenne | CELEX:52025AE4332 – JOIN(2025) 27 final | Avis du CESE (référé facultatif) sur la Communication conjointe « Préserver la paix – Feuille de route de préparation de la défense 2030 » (JOIN(2025) 27 final). Le texte soutient l'ambition de renforcer la readiness militaire européenne dans un contexte de retour de la guerre sur le continent et de recomposition des équilibres géopolitiques. Le rapporteur Christian MOOS (DE, Groupe III) et le co-rapporteur Christophe TYTGAT (BE, Catégorie 1) ont fait adopter l'avis en séance plénière le 18 mars 2026 (vote : 201/4/15). L'avis insiste sur la nécessaire accélération de la Base industrielle et technologique de défense européenne (BITDE), l'augmentation des budgets de défense et la réduction des dépendances industrielles critiques. Texte publié au JO C/2026/3231 du 2.7.2026. | [https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE4332](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE4332) |
| CELEX:52026AE0134 – COM(2025) 845 final | Comité économique et social européen (CESE) / Commission européenne | 2026-07-02 | Union européenne | CELEX:52026AE0134 – COM(2025) 845 final | Avis du CESE sur la Communication de la Commission « Feuille de route de transformation de l'industrie européenne de la défense : libérer l'innovation disruptive pour la readiness » (COM(2025) 845 final). L'avis encourage l'adoption de technologies civiles duales (IA, quantique, drones autonomes, fabrication additive) et plaide pour un cadre réglementaire simplifié afin d'accélérer l'innovation. Rapporteur Maurizio MENSI (IT, Groupe III), co-rapporteur Christophe TYTGAT (BE). Adopté en plénière le 18 mars 2026 (vote : 197/3/6). Publié au JO C/2026/3232 du 2.7.2026. Le texte mentionne explicitement les enjeux de cybersécurité, de dual-use civilo-militaire et de financement des start-ups deep-tech. | [https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AE0134](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AE0134) |
| CELEX:52025AE3786 – Avis exploratoire | Comité économique et social européen (CESE) | 2026-07-02 | Union européenne (à la demande de la Présidence chypriote) | CELEX:52025AE3786 – Avis exploratoire | Avis exploratoire demandé par la Présidence chypriote du Conseil de l'UE sur l'amélioration de la qualité de l'emploi et des conditions de travail par l'introduction et la promotion d'outils y compris d'IA, et le renforcement du dialogue social et de la négociation collective. Le CESE souligne l'impact de l'IA et du management algorithmique sur les conditions de travail, la surveillance des salariés et la nécessité d'un cadre négocié. Rapporteur Nicoletta MERLO. Avis adopté en section le 24.2.2026 et en plénière le 18.3.2026 (vote : 157/77/10). Publié au JO C/2026/3220 du 2.7.2026. | [https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE3786](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE3786) |
| C/2026/3220 ; C/2026/3231 ; C/2026/3232 (JO C du 2.7.2026) | Journal officiel de l'Union européenne | 2026-07-02 | Union européenne | C/2026/3220 ; C/2026/3231 ; C/2026/3232 (JO C du 2.7.2026) | Publication au Journal officiel de l'UE, série C, en date du 2 juillet 2026, de trois textes du Comité économique et social européen : (1) Avis sur la Feuille de route 2030 pour la défense (C/2026/3231), (2) Avis sur la transformation de l'industrie européenne de la défense (C/2026/3232), (3) Avis exploratoire sur l'emploi, l'IA et le dialogue social demandé par la Présidence chypriote (C/2026/3220). Les identifiants ELI associés permettent une vérification d'authenticité via le portail EUR-Lex. | [https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE3786](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE3786)<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE4332](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52025AE4332)<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AE0134](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AE0134) |
| U.S. v. Alarum Technologies / NetNut – Popa botnet | Federal Bureau of Investigation (FBI), Internal Revenue Service Criminal Investigation, avec Google Threat Intelligence Group, Lumen, Shadowserver, Synthient | 2026-07-02 | États-Unis (avec coordination internationale) | U.S. v. Alarum Technologies / NetNut – Popa botnet | Le FBI a saisi plusieurs centaines de domaines liés au réseau de proxy résidentiel NetNut (alias Popa), exploité par la société israélienne cotée Alarum Technologies (NASDAQ : ALAR). Le botnet, estimé à au moins 2 millions de nœuds (smart TV, box de streaming, smartphones Android), était alimenté par des SDK dissimulés dans des applications grand public et proposait ses services en marque blanche à de nombreux revendeurs. Google a désactivé les comptes Google utilisés pour le C2 du malware et bloqué les applications intégrant les SDK NetNut via Google Play Protect. En juin 2026, GTIG a observé 316 clusters distincts de groupes cybercriminels et espions utilisant les nœuds de sortie NetNut (attaques par pulvérisation de mots de passe, prise de contrôle de comptes, fraude publicitaire, scraping). Cette opération fait suite au démantèlement du réseau concurrent IPIDEA en janvier 2026. Le conseil légal d'Alarum, Omer Weiss, a déclaré que la société coopérait avec les enquêteurs. | [https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)<br>[https://cloud.google.com/blog/topics/threat-intelligence/google-continued-disruption-residential-proxy-networks/](https://cloud.google.com/blog/topics/threat-intelligence/google-continued-disruption-residential-proxy-networks/) |
| High Court of the Republic of Singapore – Injunction du 13.6.2026 ; High Court of Bombay | High Court of the Republic of Singapore ; High Court of Bombay | 2026-07-02 | Singapour / Inde (tentative d'effet extraterritorial) | High Court of the Republic of Singapore – Injunction du 13.6.2026 ; High Court of Bombay | Global Schools Holdings Pte. Ltd., via son cabinet RHTLaw Asia, a mis en demeure DataBreaches.net le 22 juin 2026 en se prévalant de deux injonctions : (1) une ordonnance de la High Court de Bombay, (2) une ordonnance de la High Court de la République de Singapour du 13 juin 2026, visant notamment FulcrumSec, Julien Mousqueton (ransomware[.]live), hendryadrian[.]com et Robert J Carloff (cybernewslive). Les deux décisions ont été rendues avant la publication par DataBreaches d'informations sur une violation de données massive touchant Global Schools Group. DataBreaches, entité enregistrée aux États-Unis, conteste toute compétence des juridictions indienne et singapourienne et alerte sur le risque de chilling effect sur la presse spécialisée en cybersécurité, particulièrement en l'absence de dispositions protégeant explicitement le rôle des médias dans des ordonnances rendues ex parte. | [https://databreaches.net/2026/07/02/global-schools-holdings-cites-two-injunctions-in-a-bid-to-chill-our-reporting-it-wont-work/](https://databreaches.net/2026/07/02/global-schools-holdings-cites-two-injunctions-in-a-bid-to-chill-our-reporting-it-wont-work/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Fabrication électronique / sous-traitance industrielle** | Tata Electronics | Données techniques et propriété intellectuelle de clients (potentiellement Apple, Tesla et autres), informations de conception et de fabrication, secrets industriels liés à la production de composants électroniques. | Inconnu | [https://rocket-boys.co.jp/security-measures-lab/tata-electronics-cyberattack-apple-tesla-leak/](https://rocket-boys.co.jp/security-measures-lab/tata-electronics-cyberattack-apple-tesla-leak/) |
| **Assurance / Services financiers** | Aflac Japon (filiale japonaise d'Aflac) | Informations personnelles d'environ 4,38 millions de clients (noms, adresses, numéros de téléphone, emails, dates de naissance) et coordonnées bancaires (numéros de compte). | 4380000 | [https://cyber.netsecops.io/articles/aflac-japan-suffers-data-breach-exposing-customer-bank-information/](https://cyber.netsecops.io/articles/aflac-japan-suffers-data-breach-exposing-customer-bank-information/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-45659** | 8.8 | 3.02% | TRUE | Microsoft SharePoint Enterprise Server 2016, Microsoft SharePoint Server 2019, Microsoft SharePoint Server Subscription Edition | CWE-502: Deserialization of Untrusted Data | Compromission totale du serveur SharePoint avec exécution de code arbitraire en tant que compte de service, ouvrant la voie à du mouvement latéral, de la persistance (web shells, tâches planifiées), de l'exfiltration de documents internes, de l'usurpation d'identité via les intégrations et potentiellement d'une compromission de l'Active Directory. Compte tenu du positionnement de SharePoint au cœur de la confiance métier, l'impact peut rapidement s'étendre à l'ensemble du système d'information. | Active | Appliquer sans délai les correctifs Microsoft publiés fin mai 2026 sur toutes les instances SharePoint Server Subscription Edition, 2019 et 2016. Cartographier toutes les instances (internes et exposées Internet) et les patcher immédiatement. Renforcer la surveillance des logs d'authentification SharePoint, chasser les web shells et artefacts de persistance, valider et restreindre les droits d'accès SharePoint, et adopter une gestion des correctifs pilotée par la menace avec traitement des CVE KEV sous 24 à 48 heures. | [https://thecyberthrone.in/2026/07/02/cisa-adds-cve-2026-45659-sharepoint-vulnerability-to-kev/](https://thecyberthrone.in/2026/07/02/cisa-adds-cve-2026-45659-sharepoint-vulnerability-to-kev/)<br>[https://securityaffairs.com/194654/security/u-s-cisa-adds-a-microsoft-sharepoint-server-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/194654/security/u-s-cisa-adds-a-microsoft-sharepoint-server-flaw-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-46817** | 9.8 | 0.68% | FALSE | Oracle Payments | Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Payments.  Successful attacks of this vulnerability can result in takeover of Oracle Payments. | Compromission potentielle d'environ 950 instances Oracle EBS exposées, avec risques d'exécution de code, d'exfiltration de données métier et financières sensibles, de sabotage d'ERP, et de pivot vers le SI interne. L'exploitation active suggère une fenêtre de risque immédiate pour les organisations n'ayant pas appliqué les correctifs Oracle. | Active | Appliquer immédiatement le correctif Oracle pour CVE-2026-46817 sur toutes les instances E-Business Suite. Inventorier les instances exposées sur Internet et réduire leur surface d'attaque (WAF, VPN, segmentation). Renforcer la surveillance des logs applicatifs et réseau, chasser les indicateurs de compromission, et engager une revue de sécurité complète des ERP exposés. | [https://securityaffairs.com/194654/security/u-s-cisa-adds-a-microsoft-sharepoint-server-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/194654/security/u-s-cisa-adds-a-microsoft-sharepoint-server-flaw-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-48276** | 10.0 | 0.92% | FALSE | ColdFusion | Unrestricted Upload of File with Dangerous Type (CWE-434) | À défaut de correctif, un attaquant peut exécuter du code arbitraire sur le serveur ColdFusion, menant potentiellement à la compromission complète de l'hôte, à l'accès aux données applicatives, à du mouvement latéral et au déploiement de charges malveillantes persistantes. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10 selon la version déployée. Restreindre l'exposition réseau, surveiller les uploads et renforcer la défense en profondeur autour des instances ColdFusion. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48283** | 10.0 | 0.63% | FALSE | ColdFusion | Unrestricted Upload of File with Dangerous Type (CWE-434) | Risque maximal d'exécution de code arbitraire sur les serveurs ColdFusion non patchés, pouvant conduire à la compromission totale de l'hôte, à l'exfiltration de données et au pivot latéral dans le SI. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10. Renforcer la segmentation réseau, surveiller les processus et flux réseau, et valider l'intégrité des applications ColdFusion après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48277** | 10.0 | 0.85% | FALSE | ColdFusion | Improper Input Validation (CWE-20) | Risque maximal d'exécution de code arbitraire sur les serveurs ColdFusion non patchés, avec compromission potentielle de l'hôte et des données applicatives. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10, segmenter le réseau, surveiller les processus et logs ColdFusion, et vérifier l'intégrité des fichiers après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48281** | 10.0 | 0.85% | FALSE | ColdFusion | Improper Input Validation (CWE-20) | Risque maximal d'exécution de code arbitraire sur les serveurs ColdFusion non patchés. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10, segmenter le réseau, surveiller les processus et logs ColdFusion, vérifier l'intégrité des fichiers après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48316** | 10.0 | N/A | FALSE | Adobe ColdFusion (2023 et 2025) | Validation d'entrée insuffisante menant à l'exécution de code arbitraire (RCE) | Risque maximal d'exécution de code arbitraire sur les serveurs ColdFusion non patchés. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10, segmenter le réseau, surveiller les processus et logs ColdFusion, vérifier l'intégrité des fichiers après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48282** | 10.0 | 1.02% | FALSE | ColdFusion | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (CWE-22) | Risque maximal d'exécution de code arbitraire et/ou d'accès non autorisé à des fichiers sensibles sur les serveurs ColdFusion non patchés. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10, segmenter le réseau, surveiller les accès fichiers et processus, vérifier l'intégrité du système après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48313** | 9.3 | 0.48% | FALSE | ColdFusion | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (CWE-22) | Divulgation d'informations sensibles hébergées sur le serveur ColdFusion (configuration, credentials, données applicatives) avec risque d'utilisation pour des attaques ultérieures. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10, segmenter le réseau, surveiller les accès fichiers et processus, vérifier l'intégrité du système après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48315** | 9.3 | 0.55% | FALSE | ColdFusion | Improper Input Validation (CWE-20) | Escalade de privilèges permettant à un attaquant authentifié d'obtenir des droits élevés sur le serveur ColdFusion et d'accéder à des fonctionnalités administratives ou à d'autres données sensibles. | None | Appliquer immédiatement ColdFusion 2023 Update 21 ou ColdFusion 2025 Update 10, segmenter le réseau, surveiller les changements de privilèges et les exécutions de processus, vérifier l'intégrité du système après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-48286** | 10.0 | 0.71% | FALSE | Adobe Campaign Classic (ACC) | Incorrect Authorization (CWE-863) | Risque maximal d'exécution de code arbitraire sur les serveurs Adobe Campaign Classic non patchés, avec compromission potentielle des données marketing et personnelles traitées. | None | Appliquer immédiatement le correctif Adobe fourni, segmenter le réseau, surveiller les accès et processus, vérifier l'intégrité du système après patch. | [https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html](https://securityaffairs.com/194622/security/adobe-fixed-multiple-maximum-severity-flaws-in-coldfusion-and-campaign-classic.html) |
| **CVE-2026-20191** | 7.5 | 0.76% | FALSE | Cisco Catalyst Center | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Divulgation potentielle de données de configuration réseau sensibles hébergées sur Cisco Catalyst Center, facilitant la reconnaissance et la préparation d'attaques ultérieures. | None | Appliquer immédiatement le correctif Cisco GSMU100 pour Catalyst Center 2.3.7 ou GSMU200 pour la branche 3.1, segmenter le réseau, surveiller les accès et processus, vérifier l'intégrité après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20213** | 7.5 | 0.46% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Interruption du service d'antivirus ClamAV, pouvant conduire à une fenêtre de détection réduite pendant laquelle des fichiers malveillants peuvent ne pas être analysés. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche, ainsi que les correctifs Cisco associés pour Secure Endpoint Connector (1.27.21 Mac, 1.29.01 Linux, 8.6.21 Windows, Secure Endpoint Private Cloud 4.2.8). Surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20214** | 7.5 | 0.46% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Interruption du service d'antivirus ClamAV avec fenêtre de détection réduite. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche et les correctifs Cisco associés, surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20215** | 7.5 | 0.39% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Interruption du service d'antivirus ClamAV avec fenêtre de détection réduite. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche et les correctifs Cisco associés, surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20216** | 7.5 | 0.39% | FALSE | Cisco Secure Endpoint | CWE-770 Allocation of Resources Without Limits or Throttling | Interruption du service d'antivirus ClamAV avec fenêtre de détection réduite. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche et les correctifs Cisco associés, surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20217** | 7.5 | 0.39% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Interruption du service d'antivirus ClamAV avec fenêtre de détection réduite. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche et les correctifs Cisco associés, surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20243** | 7.5 | 0.39% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Interruption du service d'antivirus ClamAV avec fenêtre de détection réduite. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche et les correctifs Cisco associés, surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-20244** | 7.5 | 0.39% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Interruption du service d'antivirus ClamAV avec fenêtre de détection réduite. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche et les correctifs Cisco associés, surveiller la santé du service après patch. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0825/) |
| **CVE-2026-41676** | 7.2 | 0.30% | FALSE | rust-openssl | CWE-787: Out-of-bounds Write | Impact non précisément défini par l'éditeur ; à traiter avec la même priorité que les autres CVE ClamAV publiées simultanément. | None | Appliquer immédiatement ClamAV 1.5.3 ou 1.4.5 selon la branche, surveiller la santé du service et consulter le bulletin éditeur pour plus de détails. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0824/) |
| **CVE-2026-54763** | N/A | N/A | FALSE | Traefik v2.11.x (antérieures à v2.11.51), v3.6.x (antérieures à v3.6.22), v3.7.x (antérieures à v3.7.6) | Contournement de la politique de sécurité (security policy bypass) | Contournement de la politique de sécurité sur les instances Traefik affectées, pouvant conduire à un accès non autorisé à des services internes ou à un détournement du trafic applicatif. | None | Mettre à jour Traefik vers v2.11.51, v3.6.22 ou v3.7.6 selon la branche utilisée. Appliquer les bulletins de sécurité éditeur GHSA-3q9r-p662-5j8m, GHSA-6p8f-p8j2-rqmv et GHSA-x677-9fxg-v5c5. Vérifier les configurations de middlewares après mise à jour. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0823/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0823/)<br>[https://github.com/traefik/traefik/security/advisories/GHSA-3q9r-p662-5j8m](https://github.com/traefik/traefik/security/advisories/GHSA-3q9r-p662-5j8m)<br>[https://www.cve.org/CVERecord?id=CVE-2026-54763](https://www.cve.org/CVERecord?id=CVE-2026-54763) |
| **CVE-2026-54764** | N/A | N/A | FALSE | Traefik v2.11.x (antérieures à v2.11.51), v3.6.x (antérieures à v3.6.22), v3.7.x (antérieures à v3.7.6) | Contournement de la politique de sécurité (security policy bypass) | Contournement des règles de sécurité configurées sur Traefik, exposition possible de ressources internes. | None | Mettre à jour Traefik vers v2.11.51, v3.6.22 ou v3.7.6. Appliquer le bulletin GHSA-6p8f-p8j2-rqmv. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0823/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0823/)<br>[https://github.com/traefik/traefik/security/advisories/GHSA-6p8f-p8j2-rqmv](https://github.com/traefik/traefik/security/advisories/GHSA-6p8f-p8j2-rqmv)<br>[https://www.cve.org/CVERecord?id=CVE-2026-54764](https://www.cve.org/CVERecord?id=CVE-2026-54764) |
| **CVE-2026-54765** | N/A | N/A | FALSE | Traefik v2.11.x (antérieures à v2.11.51), v3.6.x (antérieures à v3.6.22), v3.7.x (antérieures à v3.7.6) | Contournement de la politique de sécurité (security policy bypass) | Bypass des contrôles de sécurité sur le proxy, exposition potentielle de services internes. | None | Mettre à jour Traefik vers v2.11.51, v3.6.22 ou v3.7.6. Appliquer le bulletin GHSA-x677-9fxg-v5c5. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0823/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0823/)<br>[https://github.com/traefik/traefik/security/advisories/GHSA-x677-9fxg-v5c5](https://github.com/traefik/traefik/security/advisories/GHSA-x677-9fxg-v5c5)<br>[https://www.cve.org/CVERecord?id=CVE-2026-54765](https://www.cve.org/CVERecord?id=CVE-2026-54765) |
| **CVE-2026-57962** | 5.3 | 0.22% | FALSE | Thunderbird | Atteinte à l'intégrité des données / Déni de service | Corruption de données stockées localement dans le profil Thunderbird, déni de service sur le client de messagerie. | None | Mettre à jour Thunderbird vers 140.12.1 ou 152.0.1. Appliquer les bulletins mfsa2026-63 et mfsa2026-64. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0827/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0827/)<br>[https://www.mozilla.org/en-US/security/advisories/mfsa2026-63/](https://www.mozilla.org/en-US/security/advisories/mfsa2026-63/)<br>[https://www.cve.org/CVERecord?id=CVE-2026-57962](https://www.cve.org/CVERecord?id=CVE-2026-57962) |
| **CVE-2026-57963** | 6.5 | 0.19% | FALSE | Thunderbird | Atteinte à l'intégrité des données / Déni de service | Corruption de données du profil Thunderbird, déni de service client. | None | Mettre à jour Thunderbird vers 140.12.1 ou 152.0.1. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0827/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0827/)<br>[https://www.mozilla.org/en-US/security/advisories/mfsa2026-64/](https://www.mozilla.org/en-US/security/advisories/mfsa2026-64/)<br>[https://www.cve.org/CVERecord?id=CVE-2026-57963](https://www.cve.org/CVERecord?id=CVE-2026-57963) |
| **CVE-2026-4360** | 2.0 | 0.30% | FALSE | CPython | CWE-281 | Contournement de contrôles de sécurité dans les applications Python utilisant une version vulnérable de CPython. | None | Appliquer le dernier correctif de sécurité CPython publié par la Python Software Foundation (bulletin TWZW2PC2AZOV6FENIHFSRC63OM7MBGSB du 30 juin 2026). Mettre à jour les images Docker et environnements virtualenv. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0828/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0828/)<br>[https://mail.python.org/archives/list/security-announce@python.org/thread/TWZW2PC2AZOV6FENIHFSRC63OM7MBGSB/](https://mail.python.org/archives/list/security-announce@python.org/thread/TWZW2PC2AZOV6FENIHFSRC63OM7MBGSB/)<br>[https://www.cve.org/CVERecord?id=CVE-2026-4360](https://www.cve.org/CVERecord?id=CVE-2026-4360) |
| **CVE-2026-12166** | 5.5 | N/A | FALSE | GameFirst Anti-Cheat | CWE-476 NULL Pointer Dereference | Crash système (BSOD) via accès mémoire NULL, instabilité et indisponibilité du poste. | None | Restreindre l'accès local aux postes de confiance, surveiller les interactions non autorisées avec GFAC, désactiver ou supprimer les jeux utilisant GFAC en attendant un correctif éditeur. | [https://kb.cert.org/vuls/id/639124](https://kb.cert.org/vuls/id/639124)<br>[https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168](https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168) |
| **CVE-2026-12167** | 7.8 | N/A | FALSE | GameFirst Anti-Cheat | CWE-284 Improper Access Control | Exposition de fonctions privilégiées du pilote à des attaquants locaux, facilitant la future exploitation et l'élévation de privilèges. | None | Restreindre l'accès local aux postes de confiance, désactiver ou supprimer les jeux utilisant GFAC.sys, surveiller les ouvertures de handles vers le port minifilter. | [https://kb.cert.org/vuls/id/639124](https://kb.cert.org/vuls/id/639124)<br>[https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168](https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168) |
| **CVE-2026-12168** | 7.8 | N/A | FALSE | GameFirst Anti-Cheat | CWE-123 Write-What-Where Condition | Élévation de privilèges vers SYSTEM, exécution de code arbitraire en contexte noyau, compromission totale du poste. | Theoretical | Restreindre l'accès local, désactiver ou supprimer GFAC.sys/jeux utilisant GFAC, surveiller les écritures mémoire noyau suspectes et les élévations SYSTEM non autorisées. | [https://kb.cert.org/vuls/id/639124](https://kb.cert.org/vuls/id/639124)<br>[https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168](https://github.com/FzRsLLaSheR/CVE-2026-12166_CVE-2026-12167_CVE-2026-12168) |
| **CVE-2022-4989** | 8.5 | N/A | FALSE | AI Suite 3 | CWE-1284: Improper Validation of Specified Quantity in Input | Élévation de privilèges locale, accès mémoire arbitraire, compromission potentielle du poste. | None | Appliquer les correctifs ASUS pour AI Suite 3, mettre à jour le logiciel vers la dernière version, supprimer ASUS AI Suite 3 si non requis. | [https://cvefeed.io/vuln/detail/CVE-2022-4989](https://cvefeed.io/vuln/detail/CVE-2022-4989) |
| **CVE-2026-8921** | 8.5 | N/A | FALSE | ASUS Business Manager | CWE-73 External control of file name or path | Exécution de code arbitraire avec privilèges SYSTEM via manipulation de messages IPC. | None | Mettre à jour ASUS Business Manager selon l'avis de sécurité ASUS. Vérifier l'installation du correctif. | [https://cvefeed.io/vuln/detail/CVE-2026-8921](https://cvefeed.io/vuln/detail/CVE-2026-8921) |
| **CVE-2026-13768** | 9.5 | N/A | FALSE | Gardyn Home Firmware, Gardyn Studio Firmware, Gardyn Cloud API | CWE-798 | Énumération du parc d'appareils Gardyn, exécution de commandes arbitraires sur les appareils, pivot vers le réseau local de l'utilisateur, compromission complète de l'écosystème IoT Gardyn. | Theoretical | Révoquer et réémettre la clé iothubowner compromise. Mettre en œuvre des contrôles d'accès stricts pour les fonctions IoT Hub. Désactiver/restaurer l'exécution de commandes distantes si non requise. Segmenter le réseau utilisateur pour limiter le pivot. Se référer à l'avis CISA ICSA-26-183-03 et à l'ICSA-26-055-03. | [https://cvefeed.io/vuln/detail/CVE-2026-13768](https://cvefeed.io/vuln/detail/CVE-2026-13768)<br>[https://www.cisa.gov/news-events/ics-advisories](https://www.cisa.gov/news-events/ics-advisories) |
| **CVE-2026-13053** | 8.6 | N/A | FALSE | Fireware OS | CWE-787 Out-of-bounds Write | Compromission complète de l'appliance Firebox par un administrateur malveillant ou un compte privilégié volé, pouvant mener à une interception du trafic, un pivot vers le réseau interne et un contournement des politiques de sécurité périmétriques. | Theoretical | Mettre à jour Fireware OS vers une version corrigée (≥ 11.12.4_Update1 pour la branche 11.x, ≥ 12.12 pour la branche 12.x, ≥ 2026.2 pour la branche 2025.1). Restreindre l'accès au CLI de management à des administrateurs de confiance, appliquer le MFA, journaliser finement les actions privilégiées et tester la mise à jour avant redéploiement. | [https://cvefeed.io/vuln/detail/CVE-2026-13053](https://cvefeed.io/vuln/detail/CVE-2026-13053) |
| **CVE-2026-13050** | 8.6 | N/A | FALSE | Fireware OS | CWE-787 Out-of-bounds Write | Exécution de code arbitraire sur les appliances WatchGuard Firebox par un administrateur compromis, ouvrant la voie à un pivot réseau, à la modification des politiques de filtrage et au déploiement de malware persistant sur l'équipement de sécurité. | Theoretical | Mettre à jour Fireware OS vers une version post-11.12.4_Update1 (branche 11.x), post-12.12 (branche 12.x) ou post-2026.2 (branche 2025.1). Restreindre l'accès à la Management Web UI à un réseau isolé, activer l'authentification forte pour les comptes d'administration et vérifier l'intégrité des configurations après la mise à jour. | [https://cvefeed.io/vuln/detail/CVE-2026-13050](https://cvefeed.io/vuln/detail/CVE-2026-13050) |
| **CVE-2026-13054** | 8.6 | N/A | FALSE | Fireware OS | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Persistance et élévation de privilèges sur le Firebox par dépôt de fichiers malveillants, compromission de la fonction périmétrique, redirection du trafic et pivot vers le réseau interne. | Theoretical | Mettre à jour Fireware OS vers les versions corrigées (>11.12.4_Update1, >12.12, >2026.2). Restreindre l'accès Web UI à un réseau isolé, superviser l'intégrité des fichiers système et minimiser les comptes disposant des privilèges d'écriture. Surveiller toute nouvelle écriture dans des répertoires de configuration. | [https://cvefeed.io/vuln/detail/CVE-2026-13054](https://cvefeed.io/vuln/detail/CVE-2026-13054) |
| **CVE-2025-5777** | 9.3 | 99.90% | TRUE | ADC, Gateway | CWE-125 Out-of-bounds Read | Compromission massive des environnements Citrix en passerelle VPN, exfiltration de données, chiffrement destructeur (wiper), pression financière via ransomware. Anubis revendique 91 victimes dont 11 en juin 2026, principalement aux États-Unis, Royaume-Uni, Australie, France et Canada, ciblant la santé, les services aux entreprises, l'industrie, la tech et la finance. | Active | Appliquer immédiatement les correctifs Citrix pour CVE-2025-5777 sur toutes les appliances NetScaler ADC et Gateway exposées en tant que Gateway ou serveur virtuel AAA. Terminer toutes les sessions VPN actives après patch, imposer la rotation des credentials, surveiller strictement l'authentification VPN depuis des ASN atypiques, segmenter l'accès aux interfaces de management, déployer une EDR robuste avec blocage BYOVD et intégrer la détection d'outils RMM non conformes. | [https://thehackernews.com/2026/07/ransomware-groups-turn-to-citrix-bleed.html](https://thehackernews.com/2026/07/ransomware-groups-turn-to-citrix-bleed.html) |
| **CVE-2026-8451** | 8.8 | 0.50% | FALSE | ADC, Gateway | awe-125 | Divulgation de données confidentielles menant à un accès non autorisé aux ressources internes, aux virtual servers et serveurs AAA, et à un risque élevé de compromission du VPN et des backends d'entreprise. | Active | Appliquer sans délai le correctif Citrix du 30 juin 2026 sur tous les NetScaler ADC/Gateway exposés. Terminer toutes les sessions actives après patch, réinitialiser les secrets périmétriques (comptes AAA, certificats, tickets), respecter la recommandation du NCSC (hxxps://advisories.ncsc.nl/2026/ncsc-2026-0216.html), et intégrer les IOC Lupovis dans les plateformes SIEM/IDS. | [https://www.security.nl/posting/943122/%27Citrix+NetScaler-lek+dag+na+bekendmaking+misbruikt+bij+aanvallen%27](https://www.security.nl/posting/943122/%27Citrix+NetScaler-lek+dag+na+bekendmaking+misbruikt+bij+aanvallen%27) |
| **CVE-2026-54430** | 5.1 | N/A | FALSE | liboauth2 | CWE-918 Server-Side Request Forgery (SSRF) | Risque d'usurpation d'identité, d'élévation de privilèges et de fuite d'informations sensibles dans les applications s'appuyant sur liboauth2. Impact à confirmer selon la nature exacte des vulnérabilités (lecture, contournement, exécution). | None | Consulter en priorité l'avis CERT.PL pour identifier les versions vulnérables et appliquer le correctif. Auditer les applications utilisant liboauth2, vérifier la signature des jetons et la rotation des clés secrètes, déployer une surveillance renforcée sur les flux OAuth2 et adapter les règles WAF. | [https://cert.pl/en/posts/2026/07/CVE-2026-54430/](https://cert.pl/en/posts/2026/07/CVE-2026-54430/) |
| **CVE-2025-3248** | 9.8 | 99.97% | TRUE | langflow | CWE-306 Missing Authentication for Critical Function | Compromission d'infrastructure IA/cloud, vol massif de secrets (clés OpenAI, Anthropic, DeepSeek, Gemini, wallets crypto), chiffrement de bases de données et wiper, perte potentielle de données exfiltrées non récupérables (clé AES générée sans persistance). | Active | Mettre à jour Langflow vers la version 1.3.0 ou ultérieure (corrigeant CVE-2025-3248), ou retirer toute instance exposée. Changer immédiatement les identifiants par défaut MinIO, auditer Nacos (désactiver CVE-2021-29441), imposer une gestion centralisée des clés API/Cloud, surveiller les tunnels Cloudflare (cloudflared), appliquer des règles de détection Sysdig adaptées et engager un programme d'audit des agents IA internes. | [https://thehackernews.com/2026/07/ai-agent-exploits-langflow-rce-to.html](https://thehackernews.com/2026/07/ai-agent-exploits-langflow-rce-to.html) |
| **CVE-2021-29441** | 8.6 | 74.82% | FALSE | nacos | CWE-290 Authentication Bypass by Spoofing | Prise de contrôle du service discovery et de la configuration, permettant la propagation de modifications malveillantes, l'accès aux bases de données (MySQL avec compte root), l'élévation de privilèges et le chiffrement de 1 342 paramètres. | Active | Appliquer les correctifs Nacos publiés, désactiver CVE-2021-29441, régénérer la clé de signature depuis 2020, renouveler tous les secrets Nacos, surveiller les endpoints d'enregistrement, auditer les comptes admin et imposer un changement de clé au déploiement. | [https://thehackernews.com/2026/07/ai-agent-exploits-langflow-rce-to.html](https://thehackernews.com/2026/07/ai-agent-exploits-langflow-rce-to.html) |
| **CVE-2026-55200** | 9.2 | 0.73% | FALSE | libssh2 | CWE-680 Integer Overflow to Buffer Overflow | Risque d'exécution de code à distance (RCE) pré-authentification sur les clients libssh2 vulnérables lorsque l'application cible le permet. La gravité est élevée (CVSS 9.2) en raison du score, mais l'exploitation réelle dépend fortement du contexte applicatif. Le principal danger réside dans l'invisibilité de la bibliothèque dans de nombreux produits embarqués, rendant l'inventaire difficile. | Active | Mettre à jour libssh2 vers la version intégrant le commit 97acf3dfda80c91c3a8c9f2372546301d4a1a7a8. Recompiler les dépendances l'embarquant (curl, PHP SSH2, workflows Git). Réaliser un inventaire SBOM exhaustif pour identifier tous les produits affectés. Limiter les connexions SSH sortantes aux serveurs de confiance. Surveiller les processus utilisant ssh2_transport_read() via EDR/NDR. Appliquer le principe de moindre privilège aux clients SSH. Déployer des règles YARA ciblées sur la fonction vulnérable. | [https://fieldeffect.com/blog/exploitarium-repository-publishes-poc-exploits](https://fieldeffect.com/blog/exploitarium-repository-publishes-poc-exploits) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="alerte-fbiic3-le-groupe-cybercriminel-teampcp"></div>

## Alerte FBI/IC3 : le groupe cybercriminel TeamPCP

### Résumé

Le FBI via l'Internet Crime Complaint Center (IC3) publie un avis consultatif dédié au groupe cybercriminel identifié sous le nom de TeamPCP, actif dans la fraude en ligne et l'arnaque aux crypto-actifs. L'avis décrit leur modus operandi, leurs cibles privilégiées (victimes individuelles et plateformes de services financiers) et appelle les victimes et professionnels à signaler toute activité liée à ce groupe. Le document est diffusé pour sensibilisation sectorielle et coopération internationale.

---

### Analyse opérationnelle

Pour les SOC et équipes anti-fraude, l'alerte impose une mise à jour des bases de renseignement et des règles de détection orientées social engineering, prise de contrôle de comptes et transactions crypto suspectes. Les équipes doivent croiser leurs signalements de fraude avec les IOC publiés par l'IC3, renforcer la surveillance UEBA sur les opérations financières atypiques et intégrer TeamPCP dans les playbooks de réponse à incident fraude. La coordination avec les services de police et les plateformes crypto est essentielle pour le traçage et le gel des fonds.

---

### Implications stratégiques

Cette publication confirme la professionnalisation des groupes cybercriminels ciblant les services financiers et crypto, avec un risque réputationnel et réglementaire élevé pour les institutions financières exposées. Les dirigeants doivent anticiper une pression accrue des régulateurs sur les dispositifs KYC/AML, la formation client et la coopération avec les forces de l'ordre. L'alerte souligne la nécessité d'une approche sectorielle coordonnée (FS-ISAC, CERT) et d'investissements accrus dans la lutte contre la fraude en ligne.

---

### Recommandations

* Intégrer TeamPCP dans la taxonomie interne des acteurs de menace suivis.
* Diffuser l'avis IC3 aux équipes fraude, conformité, KYC et support client.
* Renforcer les contrôles anti-fraude sur les opérations crypto et virements à distance.
* Vérifier la conformité des procédures de signalement IC3 et préparer un modèle de plainte.
* Participer aux échanges sectoriels (FS-ISAC, CERT) pour partager IOC et retours d'expérience.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre à jour la base de connaissance interne avec le profil de l'acteur TeamPCP (modus operandi, ciblage, outils connus).
* Diffuser l'alerte FBI/IC3 aux équipes SOC, fraude, KYC et direction des risques.
* Vérifier que les procédures de signalement IC3 sont connues et que les canaux de dépôt de plainte sont accessibles.
* Cartographier l'exposition des services financiers et crypto aux schémas d'escroquerie et de prise de contrôle de comptes.

#### Phase 2 — Détection et analyse

* Surveiller les transactions financières atypiques, notamment en crypto-actifs, en lien avec des schémas de type 'Pig Butchering' ou investment fraud.
* Détecter les ouvertures de comptes, changements de RIB et opérations à distance inhabituels.
* Corréler les signalements utilisateurs (support client) avec les indicateurs de compromission associés à TeamPCP.
* Activer les règles SIEM/UEBA sur les comportements de social engineering ciblant le service client.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les comptes compromis et bloquer les virements sortants en attente.
* Geler les fonds identifiables et collaborer avec les services de police et exchanges crypto pour traçage.
* Révoquer les jetons d'authentification et sessions actives des victimes identifiées.
* Notifier les clients impactés conformément aux obligations réglementaires locales.

#### Phase 4 — Activités post-incident

* Documenter les incidents liés à TeamPCP et partager les IOC avec les pairs sectoriels (FS-ISAC, CERT locaux).
* Calculer l'impact financier et déposer un signalement officiel auprès de l'IC3/FBI.
* Revoir les procédures de gestion de fraude et renforcer la formation anti-social engineering.
* Évaluer la nécessité d'audits KYC/AML renforcés sur les segments exposés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans l'historique les interactions avec des domaines, adresses et wallets associés à TeamPCP.
* Chasser les patterns de communication (phishing/smishing) en lien avec des usurpations d'identité d'institutions.
* Analyser les logs d'accès aux plateformes de trading crypto pour détecter des compromissions latentes.
* Cartographier les relations entre victimes et tiers suspects pour identifier d'éventuelles cellules d'opérateurs.

---

### Sources

* [https://www.ic3.gov/CSA/2026/260702.pdf](https://www.ic3.gov/CSA/2026/260702.pdf)


---

<div id="saisie-fbi-du-domaine-netnutcom-lie-au-botnet-popa"></div>

## Saisie FBI du domaine netnut[.]com lié au botnet POPA

### Résumé

Le FBI a saisi le domaine netnut[.]com dans le cadre d'une opération contre le botnet POPA, utilisé comme réseau de proxy résidentiel au service d'activités cybercriminelles. Le site officiel commercial netnut[.]io reste en ligne, soulevant des interrogations sur le rôle exact du domaine saisi (C2 réel ou simple façade). Des acteurs de la communauté sécurité (vx-underground) demandent des clarifications à Google, l'IRS, le FBI, Lumen et Shadowserver sur l'ampleur de l'opération et la nature des infrastructures impliquées.

---

### Analyse opérationnelle

Pour les équipes SOC et réseau, l'incident impose de bloquer et surveiller les domaines netnut[.]com et netnut[.]io, de rechercher dans l'historique toute communication avec ces infrastructures, et d'identifier les machines internes éventuellement infectées par le botnet POPA. Les équipes doivent également auditer l'utilisation légitime de services de proxy résidentiel, souvent détournés par des attaquants pour anonymiser leur trafic. La coopération avec Shadowserver et Lumen est recommandée pour obtenir la liste des IP compromises.

---

### Implications stratégiques

La saisie d'un service commercial de proxy résidentiel souligne la porosité entre l'écosystème proxy résidentiel 'légal' et les infrastructures cybercriminelles. Les organisations doivent réévaluer la confiance accordée à ces services, intégrés dans certaines chaînes d'OSINT, de veille ou d'e-commerce. L'épisode met en lumière le besoin d'une clarification publique des autorités sur la portée exacte des actions de police numérique et le statut des domaines associés.

---

### Recommandations

* Bloquer netnut[.]com et netnut[.]io en DNS/Proxy et surveiller toute tentative de résolution.
* Auditer l'historique des communications internes avec les infrastructures netnut et POPA.
* Demander à Shadowserver/Lumen la liste des IP compromises associées au botnet POPA.
* Réévaluer la politique d'utilisation des proxy résidentiels et services d'anonymisation tiers.
* Sensibiliser les équipes sur les risques juridiques et opérationnels liés à l'usage de services saisis par les autorités.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Documenter en interne l'opération FBI contre le botnet POPA et le domaine netnut[.]com.
* Sensibiliser les équipes sur la distinction entre netnut[.]com (saisi) et netnut[.]io (opérationnel) pour éviter toute confusion lors d'analyses.
* Mettre à jour la veille sectorielle botnet/proxy résidentiel et résident proxy services.

#### Phase 2 — Détection et analyse

* Rechercher dans les logs DNS et proxy toute résolution historique vers netnut[.]com.
* Identifier les communications sortantes vers des IP précédemment associées au service proxy résidentiel netnut.
* Détecter les schémas de trafic anormal émanant d'IP résidentielles compromises (proxy laundering).
* Croiser les IOC publiés par Shadowserver, Lumen et le FBI avec les flux internes.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer au niveau DNS/Proxy tout trafic vers netnut[.]com et netnut[.]io si non requis métier.
* Isoler les postes ayant communiqué avec l'infrastructure du botnet POPA.
* Désactiver ou auditer les comptes ayant utilisé des services de proxy résidentiel douteux.
* Révoquer les accès sensibles ayant transité par ces réseaux.

#### Phase 4 — Activités post-incident

* Documenter l'exposition de l'organisation au service netnut et estimer l'ampleur de la compromission.
* Signaler toute compromission avérée aux autorités et partager les IOC avec les communautés sectorielles.
* Revoir la politique d'utilisation des proxy résidentiels et services d'anonymisation.
* Évaluer la nécessité d'un audit forensique sur les machines compromises.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les indicateurs de compromission liés à POPA Botnet dans l'historique réseau (NetFlow, DNS, proxy).
* Identifier les machines internes infectées communiquant avec des C2 de botnet connus.
* Rechercher l'utilisation d'IP résidentielles suspectes comme relais de trafic (lateral movement ou exfiltration).
* Cartographier la relation entre le service commercial netnut et l'infrastructure criminelle POPA.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `netnut[.]com` | High |
| DOMAIN | `netnut[.]io` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1071** | Application Layer Protocol (C2 du botnet POPA) |

---

### Sources

* [https://t.me/vxunderground/9068](https://t.me/vxunderground/9068)
* [https://t.me/vxunderground/9069](https://t.me/vxunderground/9069)


---

<div id="compromise-assessments-2025-angles-morts-lolbins-et-detection-proactive"></div>

## Compromise Assessments 2025 : angles morts, LoLBins et détection proactive

### Résumé

Kaspersky publie son rapport 2025 sur les compromise assessments : 30,8% des incidents découverts sont restés non détectés plus de 3 mois, 52% des compromissions de haute sévérité dépassent ce délai, et le plus ancien incident dormait depuis 4 ans (crypto-mining sur DC). 20% des incidents sont trouvés manuellement, 60% échappent aux outils en place par absence d'alertes de confiance. 40% des web shells retrouvés résidaient dans les sauvegardes. Les attaquants s'appuient massivement sur les outils d'administration à distance et les LoLBins, présents dans toutes les missions ayant abouti à un incident. Les organisations sans monitoring continu ni threat hunting ont 84-86% d'incidents haute/moyenne sévérité. Les capacités internes de reverse-engineering réduisent fortement la sévérité. Les problèmes de communication sont à l'origine d'un tiers des compromissions manquées.

---

### Analyse opérationnelle

Les équipes SOC doivent impérativement traiter les alertes de basse confiance (20% des découvertes manuelles) et ne pas se reposer uniquement sur les détections automatisées (60% de misses). La chasse proactive doit cibler les outils RMM légitimes (AnyDesk, TeamViewer, ScreenConnect) et les LoLBins PowerShell/WMI/PsExec ainsi que les web shells dans les sauvegardes restaurées post-incident. Les investigations doivent inclure des acquisitions mémoire pour détecter PurpleFox et LionTail. Les GPO de distribution logicielle trop permissives doivent être auditées. La rétention des sauvegardes doit être couplée à un scan YARA/AV avant restauration.

---

### Implications stratégiques

Le rapport démontre que la posture « secure by design » sans monitoring continu est insuffisante : les incidents s'accumulent silencieusement et atteignent une sévérité élevée. Le déficit de maturité opérationnelle (processus, communication, capital humain) coûte plus cher qu'un investissement dans des audits réguliers et des compromise assessments indépendants. Les RSSI doivent porter au COMEX le ROI d'un threat hunting continu et d'une équipe d'analyse malware interne. La généralisation des LoLBins dans la chaîne d'attaque impose aussi une gouvernance forte des outils d'administration à distance et une cartographie des expositions.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Réaliser régulièrement des compromise assessments indépendants en complément du monitoring continu.
* Constituer une base de connaissances LoLBins/RMM avec politique d'usage autorisée.
* Former les analystes SOC à la revue des alertes de basse confiance (≈20% des incidents détectés manuellement).
* Maintenir une équipe interne capable de reverse-engineering pour réduire la sévérité des compromissions.
* Préparer des playbooks d'investigation forensique en mémoire (PurpleFox, LionTail).
* Documenter et versionner les plans de réponse; budgéter leur mise à jour itérative.

#### Phase 2 — Détection et analyse

* Activer la détection des outils RMM/LoLBins connus (AnyDesk, PsExec, PowerShell, WMI, etc.).
* Établir des détections EDR sur les web shells et scanner les sauvegardes (40% des web shells y résident).
* Revue humaine obligatoire des alertes de basse confiance.
* Détecter les activités dormantes de cryptominage sur contrôleurs de domaine (ex: cas 4 ans).
* Hunt proactif en mémoire pour malwares fileless (PurpleFox, LionTail).
* Corréler les événements réseau/logs avec la threat intelligence (dark web, TI tierces).

#### Phase 3 — Confinement, éradication et récupération

* Éviter de supprimer uniquement fichiers/registre: isoler l'hôte, révoquer les credentials, bloquer les outils RMM.
* Avant suppression, préserver les preuves via imagerie disque/mémoire.
* Mettre en quarantaine les sauvegardes suspectes et valider leur intégrité.
* Restreindre les GPO de distribution logicielle trop permissives.
* Segmenter les actifs critiques (DCs, serveurs exposés).

#### Phase 4 — Activités post-incident

* Mettre à jour le plan de réponse sur la base des leçons de chaque incident.
* Remonter les root causes (manque de détection, gestion des vulnérabilités) au COMEX.
* Suivre le cycle forensic: collecte → analyse → containment → communication → revue.
* Communiquer régulièrement avec les parties prenantes pour combler les gaps de communication identifiés.
* Planifier un audit externe annuel pour valider la posture de sécurité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts de PurpleFox (processus en mémoire, scheduled tasks, scripts).
* Chasser les implants en mémoire (LionTail, code injecté).
* Détecter les usages anormaux de LoLBins (LOLBAS Project comme baseline).
* Identifier les web shells persistants dans les sauvegardes anciennes.
* Tracker les crypto miners dormants sur les serveurs d'infrastructure.
* Intégrer les Purple Team exercises avec assistants IA pour tester la couverture de détection.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1059** | Command and Scripting Interpreter |
| **T1078** | Valid Accounts |
| **T1218** | System Binary Proxy Execution (LoLBins) |
| **T1074** | Data Staged |
| **T1505.003** | Server Software Component: Web Shell |

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1ulml1x/building_a_purple_team_ai_assistant/](https://www.reddit.com/r/redteamsec/comments/1ulml1x/building_a_purple_team_ai_assistant/)
* [https://www.reddit.com/r/redteamsec/comments/1ulo4hc/win_x64_shellcode_why_blind_peb_traversal_fails/](https://www.reddit.com/r/redteamsec/comments/1ulo4hc/win_x64_shellcode_why_blind_peb_traversal_fails/)
* [https://www.reddit.com/r/redteamsec/comments/1ulcos6/i_ported_the_lacuna_chain_technique_originally_in/](https://www.reddit.com/r/redteamsec/comments/1ulcos6/i_ported_the_lacuna_chain_technique_originally_in/)
* [https://securelist.com/compromise-assessment-findings-2025/120542/](https://securelist.com/compromise-assessment-findings-2025/120542/)


---

<div id="panneau-daffiliation-ciblant-microsoft-365-et-campagne-de-phishing-slidesgowix"></div>

## Panneau d'affiliation ciblant Microsoft 365 et campagne de phishing SlidesGo→Wix

### Résumé

Un pulse OTX publié par Tr1sa111 documente un panneau d'affiliation ciblant Microsoft 365, suggérant l'existence d'un service de phishing-as-a-service ou de revente d'accès à des comptes cloud. Une url malveillante relayée via SlidesGo redirige vers un site Wix contrôlé par un attaquant (rsadegh019[.]wixsite[.]com). L'objectif est typiquement le vol d'identifiants Microsoft 365 pour compromission de boîtes mail, accès SharePoint/OneDrive et fraudeBEC. Les données OTX sont à considérer comme préliminaires et non vérifiées.

---

### Analyse opérationnelle

Les équipes SOC doivent ajouter en bloqueurs DNS/proxy les domaines signalés (rsadegh019[.]wixsite[.]com) et traiter SlidesGo comme vecteur de redirection possible. Les alertes Identity Protection (Microsoft Entra) doivent être examinées : connexions inhabituelles, MFA fatigue, changements de règles Inbox, création d'OAuth consentements. Les passerelles email doivent scanner les liens issus de plateformes gratuites abusées. Les EDR navigateur doivent journaliser les redirections SlidesGo→Wix.

---

### Implications stratégiques

Cette cible confirme la tendance au « initial access brokerage » pour Microsoft 365 : les acteurs opportunistes revendent ou partagent des panneaux d'affiliation, abaissant le seuil d'entrée pour des attaques BEC et ransomware-as-a-service. Les RSSI doivent investir dans l'Entra ID Protection, des politiques d'accès conditionnel strictes et un programme de détection de marque (brand protection) couvrant les abus de plateformes Wix/SquareSpace/Weebly. La sensibilisation utilisateurs doit inclure explicitement les liens ouverts depuis des outils collaboratifs tiers.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs aux liens de phishing relayés par SlidesGo/Wix/SquareSpace.
* Configurer Microsoft 365 avec MFA résistante au phishing (FIDO2, Entra Certificate Auth).
* Maintenir une IOC list à jour des domaines/abuse de plateformes gratuites (Wix, Weebly, Squarespace).
* Restreindre l'accès M365 par access policies conditionnelles (device compliant, géolocalisation).

#### Phase 2 — Détection et analyse

* Surveiller les connexions M365 depuis des IP/AS inhabituels.
* Détecter les Impossible Travel et scénarios d'ATO (Account TakeOver).
* Corréler les alertes Identity Protection aux clics sur liens externes.
* Scanner les urls de phishing via les passerelles email et EDR navigateur.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les sessions M365 compromises (Revoke-AzureADUserAllRefreshToken).
* Désactiver le compte, forcer réinitialisation MFA et mot de passe.
* Bloquer en proxy/DNS les domaines d'attaque (rsadegh019[.]wixsite[.]com).
* Isoler l'hôte utilisateur, collecter l'image forensique mémoire/ disque.

#### Phase 4 — Activités post-incident

* Vérifier la création de règles mailbox/Inbox rules malveillantes.
* Auditer l'activité OAuth/Permissions accordées aux applications tierces.
* Notifier les parties impactées (DPO, juridique, clients).
* Documenter l'IOC dans la plateforme de partage (OTX/MISP) avec TLP:AMBER.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les patterns d'authentification O365 inhabituels et les tokens révoqués.
* Chasser les Conditional Access bypass et activités post-compromission sur SharePoint/OneDrive.
* Monitorer les inscriptions de domaines typosquattés via Wix/SquareSpace imitant la marque.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `otx[.]alienvault[.]com` | High |
| URL | `hxxps[:]//slidesgo[.]com/editor/external-link?target=hxxps[:]//rsadegh019[.]wixsite[.]com/my-site-2&uuid=9bbc63ba-db16-44b1-8ab0-38b072de09d4` | Medium |
| DOMAIN | `rsadegh019[.]wixsite[.]com` | Medium |
| DOMAIN | `slidesgo[.]com` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link |
| **T1078.004** | Cloud Accounts |
| **T1071** | Application Layer Protocol |

---

### Sources

* [https://otx.alienvault.com/pulse/6a4737cfa4b7348503174ce9](https://otx.alienvault.com/pulse/6a4737cfa4b7348503174ce9)


---

<div id="possible-campagne-de-phishing-utilisant-slidesgo-comme-redirecteur-vers-un-site-wix"></div>

## Possible campagne de phishing utilisant SlidesGo comme redirecteur vers un site Wix

### Résumé

Un post Mastodon signale une URL de phishing (SlidesGo vers rsadegh019[.]wixsite[.]com) détectée via URLDNA. La chaîne d'attaque exploite un service légitime de présentation (SlidesGo) pour camoufler un lien vers un site Wix contrôlé par l'attaquant. Le contenu textuel de la source est très court et la nature exacte du payload (vol d'identifiants, escroquerie, dropper) n'est pas explicitement décrite.

---

### Analyse opérationnelle

Les équipes SOC doivent ajouter en blocage proxy/DNS le domaine final et surveiller les redirections multiples à partir de SlidesGo. Les alertes issues d'URLDNA doivent être intégrées dans le SIEM. Les passerelles email doivent signaler ou réécrire les liens vers wixsite[.]com issus de domaines tiers. Les EDR doivent inspecter le contenu chargé depuis wixsite[.]com.

---

### Implications stratégiques

L'abus de plateformes gratuites à forte légitimité (SlidesGo, Google Docs, SharePoint, Wix) continue d'être un vecteur de phishing difficile à filtrer sans analyse du contenu de la page. Les RSSI doivent investir dans des solutions de sandboxing d'URL et de prise d'empreinte visuelle. La formation utilisateurs doit insister sur le fait qu'un service de confiance peut servir de point d'entrée vers un site malveillant.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs aux liens provenant de plateformes gratuites (SlidesGo).
* Durcir la passerelle email contre les liens ouverts externes.
* Maintenir une IOC list partagée des domaines d'attaque.

#### Phase 2 — Détection et analyse

* Détecter via proxy les redirections vers wixsite[.]com depuis slidesgo[.]com.
* Analyser via URLDNA ou équivalent les urls suspectes.
* Monitorer les clics sortants vers des domaines récemment créés.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer en DNS/proxy le domaine rsadegh019[.]wixsite[.]com.
* Mettre en quarantaine les emails contenant ces liens.
* Révoquer les sessions utilisateur en cas de clic confirmé.

#### Phase 4 — Activités post-incident

* Documenter l'IOC sur MISP/OTX.
* Sensibiliser les utilisateurs cliquant.
* Évaluer l'impact (vol credentials, malware drop).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les noms de domaine wixsite[.]com imitant des marques internes.
* Tracker les chaînes SlidesGo->Wix dans les logs proxy.
* Corréler avec les vagues de phishing signalées par Tr1sa111.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps[:]//slidesgo[.]com/editor/external-link?target=hxxps[:]//rsadegh019[.]wixsite[.]com/my-site-2&uuid=9bbc63ba-db16-44b1-8ab0-38b072de09d4` | Medium |
| DOMAIN | `rsadegh019[.]wixsite[.]com` | Medium |
| DOMAIN | `slidesgo[.]com` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link |
| **T1036** | Masquerading |

---

### Sources

* [https://infosec.exchange/@urldna/116854279978587483](https://infosec.exchange/@urldna/116854279978587483)


---

<div id="rapport-de-tendances-des-techniques-dattaque-q2-2026-ahnlab-asec"></div>

## Rapport de tendances des techniques d'attaque Q2 2026 (AhnLab ASEC)

### Résumé

AhnLab ASEC publie son rapport trimestriel Q2 2026 sur les techniques d'attaque observées. Le texte de l'article dans le flux est vide et seules les métadonnées structurelles sont disponibles : aucun détail, aucun TTP, aucun IOC ne peut être extrait.

---

### Analyse opérationnelle

Sans contenu exploitable dans la source, les équipes SOC doivent consulter directement le rapport AhnLab pour en extraire les TTP, signatures et IOC pertinents, puis mettre à jour les règles de détection et les playbooks en conséquence.

---

### Implications stratégiques

Les bulletins trimestriels d'éditeurs comme AhnLab offrent une vision sectorielle et régionalisée (Asie). Les RSSI doivent les intégrer dans une veille multi-sources (threat intel dupliquée) pour anticiper les évolutions de techniques et calibrer les investissements défensifs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* S'abonner aux bulletins trimestriels AhnLab et intégrer les TTP publiés au programme de détection interne.
* Mapper les nouvelles techniques aux détections EDR/SIEM existantes.
* Former les analystes aux évolutions d'attaques observées au Q2.

#### Phase 2 — Détection et analyse

* Implémenter les signatures/IOC publiés dans le rapport Q2 2026.
* Renforcer la surveillance sur les techniques en hausse identifiées par AhnLab.

#### Phase 3 — Confinement, éradication et récupération

* Mettre à jour les règles de blocage sur la base des indicateurs publiés.
* Isoler rapidement les hôtes présentant les comportements signalés.

#### Phase 4 — Activités post-incident

* Comparer les incidents internes aux tendances sectorielles du Q2.
* Ajuster les KPIs SOC en fonction de l'évolution du paysage.

#### Phase 5 — Threat Hunting (proactif)

* Intégrer les TTPs Q2 2026 dans les scénarios de purple team.
* Hypothèse-driven hunting basée sur les familles de techniques signalées.

---

### Sources

* [https://asec.ahnlab.com/en/94320/](https://asec.ahnlab.com/en/94320/)


---

<div id="catan-and-mouse-cisco-talos-intelligence"></div>

## Catan and Mouse (Cisco Talos Intelligence)

### Résumé

L'article « Catan and Mouse » publié sur le blog Talos Intelligence est référencé dans le flux, mais le contenu textuel accessible est vide (intitulé « Intelligence Center »). Aucun détail technique, TTP, IOC ou campagne ne peut être extrait de la source fournie.

---

### Analyse opérationnelle

L'information disponible est insuffisante pour produire une analyse opérationnelle détaillée. Les équipes SOC doivent consulter directement l'article sur blog.talosintelligence.com et appliquer les éventuels IOC/TTPs publiés.

---

### Implications stratégiques

Le titre évoque une publication Talos potentiellement liée à une nouvelle campagne d'attaquant ou à un jeu de chat et souris défensif. Sans contenu exploitable, aucune implication stratégique précise ne peut être tirée ; néanmoins, suivre les publications Talos reste essentiel dans une veille threat intel multi-sources.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Suivre les publications Talos Intelligence pour enrichir la base de connaissance interne.
* Préparer des playbooks pour les TTPs émergents cités par Talos.

#### Phase 2 — Détection et analyse

* Activer les détections basées sur les IOC partagés par Talos.
* Implémenter les signatures Snort/Sigma publiées par Cisco Talos.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les IOC réseau, isoler les hôtes compromis selon les TPs Talos.

#### Phase 4 — Activités post-incident

* Documenter les incidents liés et partager en interne les enseignements.

#### Phase 5 — Threat Hunting (proactif)

* Utiliser les IOC et TTP Talos pour des campagnes de threat hunting ciblées.

---

### Sources

* [https://blog.talosintelligence.com/catan-and-mouse/](https://blog.talosintelligence.com/catan-and-mouse/)


---

<div id="shinyhunters-revendique-le-vol-de-plus-de-40-go-de-donnees-a-luniversite-de-nottingham"></div>

## ShinyHunters revendique le vol de plus de 40 Go de données à l'Université de Nottingham

### Résumé

Le groupe d'extorsion ShinyHunters revendique le vol de plus de 40 Go de données auprès de l'Université de Nottingham, incluant des adresses e-mail, numéros de téléphone, adresses postales, dossiers de facturation et données financières d'étudiants. La revendication a été publiée le 10 juin 2026 sur la plateforme Yazoul et reste, à la date de l'alerte (2 juillet 2026), non vérifiée et en cours d'analyse.

---

### Analyse opérationnelle

Pour les SOC/IT du secteur de l'enseignement supérieur, cette alerte impose une surveillance rapprochée des leak sites ShinyHunters et un audit urgent des accès aux systèmes de facturation, de scolarité et de finance. La défense doit prioriser la protection des comptes à privilèges (vecteur récurrent du groupe), durcir le MFA, renforcer la DLP sur les bases de données étudiants/alumni et préparer un plan de réponse à notification RGPD massive. Le secteur académique reste une cible privilégiée du fait de son patrimoine de données personnelles et de sa surface d'attaque distribuée (multiples portails, SSO, tiers).

---

### Implications stratégiques

Cette nouvelle attaque illustre la persistance de ShinyHunters comme menace récurrente pour le secteur académique et la recherche, avec un risque réputationnel, réglementaire (ICO, CNIL, sanctions RGPD) et financier majeur. Elle souligne la tendance à la monétisation de données exfiltrées via la double extorsion et la nécessité d'une gouvernance renforcée des sous-traitants (cloud, plateformes pédagogiques). Les directions d'université doivent intégrer la cyber-résilience comme un enjeu stratégique, au-delà du simple cadre IT.

---

### Recommandations

* Activer une veille darkweb ciblée sur le domaine institutionnel et ses sous-domaines.
* Réaliser un audit des accès aux ERP finances/scolarité et imposer MFA + moindre privilège.
* Préparer les communications de crise et la notification RGPD (ICO au RU).
* Tester les procédures de réponse à incident via un exercice tabletop.
* Évaluer la couverture cyber-assurance pour les conséquences d'une fuite massive.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des données personnelles, académiques et financières stockées (étudiants, anciens élèves, personnel).
* Cartographier les flux de données sensibles (billing, finance étudiante, dossiers RH) et prioriser leur protection (chiffrement, segmentation).
* Souscrire à des flux de threat intel couvrant les leak sites des groupes d'extorsion (ShinyHunters, Scattered Spider, Lapsus$).
* Préparer des modèles de notifications CNIL/ICO et de communication de crise.
* Sensibiliser le personnel et les étudiants aux indicateurs de compromission.

#### Phase 2 — Détection et analyse

* Surveiller les apparitions du nom de domaine institutionnel sur les leak sites et forums darkweb (via Yazoul, DarkOwl, Recorded Future, etc.).
* Mettre en place une supervision des accès anormaux aux SI financiers et RH (logs IAM, ERP, SI Scolarité).
* Détecter les exfiltrations massives via DLP et EDR (volumétrie sortante inhabituelle, exports de bases).
* Analyser en priorité les comptes à privilèges et prestataires tiers (vecteur fréquent des attaques ShinyHunters).

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes concernés dès confirmation d'exfiltration et révoquer les sessions/credentials potentiellement exposés.
* Forcer la rotation des mots de passe et l'invalidation des jetons SSO pour les populations impactées.
* Activer le canal de communication de crise et informer la DPO, la direction et les autorités de contrôle (ICO au RU).
* Geler les flux sortants vers des services de partage non maîtrisés.
* Préparer la notification individuelle des personnes concernées conformément au RGPD.

#### Phase 4 — Activités post-incident

* Conduire un forensic complet pour déterminer le vecteur d'intrusion initial (phishing, credential stuffing, abuse de SaaS).
* Documenter les données réellement exposées et corréler avec les déclarations de l'attaquant.
* Renforcer la politique de moindre privilège et le MFA sur tous les accès administrateur.
* Réaliser un retour d'expérience avec les parties prenantes (IT, DPO, COM, direction).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des signes d'implantation persistante (web shells, comptes fantômes, accès API abusifs).
* Pister toute activité des affiliés ShinyHunters/Telegram sur l'institution et ses sous-traitants.
* Vérifier l'absence de revente ou de republication des données sur d'autres canaux (Telegram, forums).
* Surveiller la réutilisation d'identifiants exfiltrés dans des attaques de credential stuffing.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `nottingham[.]ac.uk` | Medium |
| DOMAIN | `yazoul[.]net` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration Over Web Service |
| **T1657** | Financial Theft |

---

### Sources

* [https://www.yazoul.net/intel/claim/2026-06-10-university-of-nottingham-hit-by-shinyhunters-june-2026](https://www.yazoul.net/intel/claim/2026-06-10-university-of-nottingham-hit-by-shinyhunters-june-2026)


---

<div id="vague-de-revendications-ransomware-lockbit-akira-et-thegentlemen-ciblant-la-tech-le-gouvernement-et-lindustrie"></div>

## Vague de revendications ransomware LockBit, Akira et TheGentlemen ciblant la tech, le gouvernement et l'industrie

### Résumé

Le 1er juillet 2026, plusieurs groupes ransomware - notamment LockBit, Akira et TheGentlemen - ont revendiqué de multiples victimes dans les secteurs de la technologie, du gouvernement et de l'industrie manufacturière. La journée a été marquée par une intensification notable de l'activité d'extorsion et de chiffrement à l'échelle mondiale.

---

### Analyse opérationnelle

Les équipes SOC doivent élever le niveau de vigilance face à la recrudescence simultanée d'attaques de plusieurs souches ransomware majeures. Priorité à la vérification de l'intégrité des sauvegardes (notamment contre la suppression via outils comme Velociraptor, Cobalt Strike, Mimikatz), à la segmentation réseau et à la détection des phases pré-encryptage (désactivation d'EDR, effacement de VSS). Les secteurs public et industriel doivent particulièrement renforcer la protection de leurs fournisseurs d'accès (VPN, RDP) et surveiller les IOC partagés par les CERT et acteurs de threat intel.

---

### Implications stratégiques

Cette convergence de revendications illustre la maturité opérationnelle de l'écosystème RaaS et la professionnalisation de la double extorsion. Les organisations doivent intégrer le risque ransomware dans leur gouvernance (NIS2, directives sectorielles), investir dans la résilience opérationnelle et revoir leurs polices cyber-assurance. La pression réglementaire et la responsabilité des dirigeants en cas de négligence avérée deviennent des enjeux décisionnels majeurs.

---

### Recommandations

* Vérifier immédiatement l'état des sauvegardes et leur isolation (air-gap, immutabilité).
* Imposer MFA sur tous les accès distants (VPN, RDP, SSO) et patcher en urgence les appliances exposées.
* Lancer une chasse proactive aux IOC LockBit/Akira et auditer les comptes à privilèges.
* Revoir les contrats cyber et préparer les notifications NIS2/RGPD.
* Sensibiliser les directions métiers aux scénarios de continuité d'activité.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une cartographie exhaustive des actifs critiques et de leurs dépendances (AD, sauvegardes, hyperviseurs).
* S'assurer que les sauvegardes sont isolées (air-gapped ou immuables) et testées régulièrement (restore drill).
* Surveiller les IOC connus de LockBit/Akira (indicateurs de compromission, hashes, ransom notes) via threat intel.
* Établir un canal de communication sécurisé avec les forces de l'ordre (Europol, ANSSI, FBI).
* Préparer des playbooks de confinement par segment réseau et des jetons de réponse (scripts, outils forensiques).

#### Phase 2 — Détection et analyse

* Détecter les signes d'encryptage massif (changements de signature de fichiers, ransom notes .lockbit, .akira).
* Surveiller les activités inhabituelles de désactivation de services de sauvegarde, d'anti-virus ou d'EDR (pré-encryptage).
* Détecter les mouvements latéraux via l'analyse des logs AD, Kerberos, RDP et SMB.
* Détecter les exfiltrations vers des services cloud non autorisés (Mega, Dropbox, serveurs C2).

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes et segments touchés du reste du réseau.
* Désactiver les comptes compromis et révoquer les tickets Kerberos (krbtgt reset si nécessaire).
* Mettre hors ligne les partages de fichiers critiques pour limiter la propagation.
* Activer le plan de continuité d'activité (PCA) et basculer sur les sauvegardes saines.
* Notifier les autorités compétentes et les partenaires impactés (clients, fournisseurs).

#### Phase 4 — Activités post-incident

* Conduire une investigation forensic pour identifier le vecteur d'entrée (phishing, exploitation VPN, credential stuffing).
* Évaluer la qualité et l'exhaustivité des données exfiltrées revendiquées.
* Reconstruire les systèmes à partir de sources fiables et non compromises.
* Communiquer de manière transparente aux parties prenantes et autorités (RGPD, NIS2).
* Renforcer la posture de sécurité (patch management, segmentation, MFA, EDR).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des implants persistants (web shells, services planifiés, tâches cron).
* Pister toute communication avec les infrastructures C2 associées à LockBit/Akira.
* Rechercher les outils de reconnaissance (PsExec, Mimikatz, Cobalt Strike, AnyDesk).
* Auditer les configurations AD et les stratégies de groupe pour limiter les mouvements latéraux.
* Suivre les leak sites pour confirmer la non-revendication ou anticiper une seconde extorsion.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `cyber[.]netsecops[.]io` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1487** | Disk Wipe or Corruption |
| **T1490** | Inhibit System Recovery |
| **T1657** | Financial Theft |
| **T1567** | Exfiltration Over Web Service |

---

### Sources

* [https://cyber.netsecops.io/articles/breachsense-documents-multiple-ransomware-attacks-july-1st/](https://cyber.netsecops.io/articles/breachsense-documents-multiple-ransomware-attacks-july-1st/)


---

<div id="un-eurodepute-charge-denqueter-sur-pegasus-lui-meme-vise-par-le-logiciel-espion"></div>

## Un eurodéputé chargé d'enquêter sur Pegasus lui-même visé par le logiciel espion

### Résumé

Selon un rapport du Citizen Lab publié le 3 juillet 2026, l'eurodéputé grec Stelios Kouloglou, qui participait à la commission d'enquête du Parlement européen sur l'utilisation de Pegasus (commission PEGA), a été infecté par le logiciel espion Pegasus à trois reprises en 2022 et 2023. C'est la première fois que Pegasus est identifié sur un appareil d'un membre de cette commission d'enquête. La découverte a été faite lorsque l'ancien parlementaire, devenu journaliste, a fait auditer son téléphone par le Citizen Lab en mai 2026.

---

### Analyse opérationnelle

Pour les équipes sécurité des institutions européennes et des organisations politiques, cette affaire impose de traiter les appareils personnels des élus et collaborateurs comme des actifs sensibles à auditer en continu. Elle démontre la capacité des États clients de NSO à cibler des parlementaires supervisant directement l'usage des outils de surveillance. Les procédures MDM, le cloisonnement des données professionnelles sur des terminaux dédiés et la collaboration avec Citizen Lab deviennent des prérequis opérationnels.

---

### Implications stratégiques

Cet épisode fragilise la crédibilité des enquêtes institutionnelles sur les spyware commerciaux et accentue la pression politique sur la Commission européenne pour durcir la régulation des outils de type Pegasus/Predator. Il renforce les arguments en faveur d'un moratoire, d'une interdiction d'export et d'un cadre de sanctions contre les acteurs du secteur. Pour les organisations, il souligne que la menace ne vise pas uniquement les opposants politiques mais aussi les mécanismes démocratiques de contrôle.

---

### Recommandations

* Auditer systématiquement les appareils des élus et des membres de commissions sensibles.
* Renforcer la coopération institutionnelle avec Citizen Lab et les CERT nationaux.
* Prévoir une politique de séparation stricte entre usages personnels et professionnels.
* Intégrer la menace spyware dans les analyses de risque politique et institutionnel.
* Soutenir les initiatives législatives de restriction des outils de surveillance mercenaires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Équiper les parlementaires, élus et personnels sensibles de smartphones dédiés et audités périodiquement.
* Maintenir une veille sur les IOC de Pegasus/NSO et Predator via Citizen Lab, Access Now et Apple Threat Notifications.
* Former les cibles à haut risque (journalistes, élus, défenseurs des droits) aux bonnes pratiques d'hygiène mobile.
* Disposer d'un canal de confiance avec Citizen Lab / Amnesty Security Lab pour analyses forensiques.
* Cartographier les appareils exposés et leur criticité (journalisme d'investigation, diplomatie, droit).

#### Phase 2 — Détection et analyse

* Activer la collecte des alertes Apple/Google de ciblage spyware.
* Monitorer les redémarrages anormaux, drains de batterie, processus suspects (ioc específicos Pegasus).
* Surveiller les anomalies réseau (DNS, certificats, flux vers infrastructures de commande).
* Détecter l'utilisation de profils MDM ou certificats non autorisés.
* Centraliser les rapports de Citizen Lab sur les IOC et les croiser avec les audits internes.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement l'appareil compromis du réseau et des comptes (messagerie, cloud).
* Procéder au remplacement de l'appareil par un terminal propre et réputé non compromis.
* Changer l'ensemble des mots de passe depuis un équipement sain et révoquer les jetons.
* Déposer plainte auprès des autorités compétentes (Cnil, Parquet, Eurojust) et notifier les institutions européennes.
* Activer la communication restreinte pour limiter les fuites d'informations sur l'identification de la cible.

#### Phase 4 — Activités post-incident

* Soliciter une analyse forensique externe (Citizen Lab, Amnesty) pour confirmer le vecteur d'infection (iMessage, WhatsApp, etc.).
* Documenter la chronologie d'infection et évaluer l'impact sur la confidentialité des travaux d'enquête.
* Renforcer la doctrine de sécurité des appareils personnels dans les institutions.
* Sensibiliser les élus et collaborateurs aux risques de ciblage.
* Suivre les procédures judiciaires et coopérer avec la commission PEGA.

#### Phase 5 — Threat Hunting (proactif)

* Auditer tous les appareils des membres d'institutions sensibles (parlement, commission, cabinets).
* Rechercher des traces de jailbreak, de profils de configuration anormaux ou de processus résidents inconnus.
* Identifier d'éventuelles compromissions antérieures non détectées dans l'entourage professionnel.
* Surveiller les réutilisations d'IOC Pegasus pour de nouveaux ciblages en Europe.
* Coordonner la veille avec les CERT nationaux et l'ENISA.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1660** | Exploitation for Credential Access |
| **T1189** | Drive-by Compromise |
| **T1078** | Valid Accounts |

---

### Sources

* [https://www.lemonde.fr/pixels/article/2026/07/03/un-eurodepute-charge-d-enqueter-sur-pegasus-lui-meme-vise-par-le-logiciel-espion_6718462_4408996.html](https://www.lemonde.fr/pixels/article/2026/07/03/un-eurodepute-charge-d-enqueter-sur-pegasus-lui-meme-vise-par-le-logiciel-espion_6718462_4408996.html)
