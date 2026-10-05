# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Curiosités des chaînes User-Agent, (dim. 4 oct.)](#curiosites-des-chaines-user-agent-dim-4-oct)
  * [Conseil de sécurité : auditez vos dépendances transitives ! 🛡️ Les applications modernes sont construites sur des couches de bibliothèques. Même si vous maintenez à jour vos imports directs, les « dépendances de dépendances » restent souvent non corrigées. Les attaquants ciblent fréquemment ces couches plus profondes pour rester sous le radar. Action : utilisez des outils SCA pour visualiser l’intégralité de votre arbre de dépendances et configurer des alertes pour les vulnérabilités dans chaque couche. Gardez une longueur d’avance sur les menaces : https://cvedatabase.com #CyberSecurity #InfoSec #CVE #AppSec](#conseil-de-securite-auditez-vos-dependances-transitives-les-applications-modernes-sont-construites-sur-des-couches-de-bibliotheques-meme-si-vous-maintenez-a-jour-vos-imports-directs-les-dependances-de-dependances-restent-souvent-non-corrigees-les-attaquants-ciblent-frequemment-ces-couches-plus-profondes-pour-rester-sous-le-radar-action-utilisez-des-outils-sca-pour-visualiser-lintegralite-de-votre-arbre-de-dependances-et-configurer-des-alertes-pour-les-vulnerabilites-dans-chaque-couche-gardez-une-longueur-davance-sur-les-menaces-httpscvedatabasecom-cybersecurity-infosec-cve-appsec)
  * [Quelqu’un était en train de s’introduire dans mes serveurs. Une IA les a interceptés, les a identifiés (Mirai, sûre à 91 %), les a bloqués et a écrit une règle pour attraper le prochain. Elle n’a pas pu déployer cette règle avant d’avoir passé 5 000 événements réels.Quatre minutes. Production en direct. Rien de scénarisé.https://youtu.be/O47Iky7LW8w#infosec #threatintel #blueteam #AI #DetectionEngineering](#quelquun-etait-en-train-de-sintroduire-dans-mes-serveurs-une-ia-les-a-interceptes-les-a-identifies-mirai-sure-a-91-les-a-bloques-et-a-ecrit-une-regle-pour-attraper-le-prochain-elle-na-pas-pu-deployer-cette-regle-avant-davoir-passe-5-000-evenements-reelsquatre-minutes-production-en-direct-rien-de-scenarisehttpsyoutubeo47iky7lw8winfosec-threatintel-blueteam-ai-detectionengineering)
  * [StrangerDOTNETThings/x509com.js - montrez-moi chaque objet COM que je peux appeler avec certutil](#strangerdotnetthingsx509comjs-montrez-moi-chaque-objet-com-que-je-peux-appeler-avec-certutil)
  * [kl-security-key listed in Pentest Tools — worth a closer look. Security keys are often treated as the final authentication layer, so understanding their attack surface matters. A tool that probes that layer is the kind of thing worth reading carefully before deploying anywhere near production. #infosec #pentest #hardware https://kitploit.com/en/tools/github/karaaslanlabs/kl-security-key](#kl-security-key-listed-in-pentest-tools-worth-a-closer-look-security-keys-are-often-treated-as-the-final-authentication-layer-so-understanding-their-attack-surface-matters-a-tool-that-probes-that-layer-is-the-kind-of-thing-worth-reading-carefully-before-deploying-anywhere-near-production-infosec-pentest-hardware-httpskitploitcomentoolsgithubkaraaslanlabskl-security-key)
  * [Bold Spring Nursery par play](#bold-spring-nursery-par-play)
  * [🚨Nouvel article de blog d’un groupe de rançongiciel !🚨Nom du groupe : kazu Titre de l’article : TGD: Digital Government Platform - AR Organisation : TGD: Digital Government Platform Localisation : 🇦🇷 AR Secteur : Gouvernement Infos : https://cti.fyi/groups/kazu.html#ransomware #cti #threatintelligence #cybersecurity #infosec](#nouvel-article-de-blog-dun-groupe-de-rancongiciel-nom-du-groupe-kazu-titre-de-larticle-tgd-digital-government-platform-ar-organisation-tgd-digital-government-platform-localisation-ar-secteur-gouvernement-infos-httpsctifyigroupskazuhtmlransomware-cti-threatintelligence-cybersecurity-infosec)
  * [La sécurité multi-locataire exige une isolation absolue jusqu’à la couche de stockage. Cloudflare a récemment partagé des détails sur la manière dont elle a traité une vulnérabilité d’exposition de données entre locataires affectant Cloudflare Containers et Cloudflare Sandboxes.](#la-securite-multi-locataire-exige-une-isolation-absolue-jusqua-la-couche-de-stockage-cloudflare-a-recemment-partage-des-details-sur-la-maniere-dont-elle-a-traite-une-vulnerabilite-dexposition-de-donnees-entre-locataires-affectant-cloudflare-containers-et-cloudflare-sandboxes)
  * [Apex Flash - un modèle à poids ouverts pour la recherche en sécurité, post-entraîné sur des vulnérabilités réelles issues de notre jeu de données propriétaire.](#apex-flash-un-modele-a-poids-ouverts-pour-la-recherche-en-securite-post-entraine-sur-des-vulnerabilites-reelles-issues-de-notre-jeu-de-donnees-proprietaire)
  * [LockBit publie des données sur d’anciens employés de Forus à la suite de l’incident signalé au CMF](#lockbit-publie-des-donnees-sur-danciens-employes-de-forus-a-la-suite-de-lincident-signale-au-cmf)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse quotidienne des volumes CTI révèle une journée dominée par les vulnérabilités (24) et les violations de données (14), représentant près de 73 % des 52 éléments collectés. Cette prépondérance technique suggère une priorité opérationnelle pour les équipes de sécurité, avec un besoin accru de gestion des correctifs et de surveillance des fuites. Les articles généraux (10) complètent ce panorama sans apporter de signaux stratégiques majeurs. En revanche, les catégories threat_actors (1), geopolitics (2) et regulatory (1) restent marginales, indiquant une accalmie relative sur les fronts géopolitique et réglementaire. Cette faible activité sur les acteurs de la menace pourrait refléter un biais de collecte ou une période de latence avant de nouvelles campagnes. Stratégiquement, il est recommandé de concentrer les ressources sur la remédiation des vulnérabilités critiques et la détection des violations de données, tout en maintenant une veille légère sur les autres axes. Une remontée soudaine des indicateurs géopolitiques ou réglementaires devra être surveillée dans les prochains jours.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Kairos** | éducation | Chiffrement (T1486), extorsion (T1657), exfiltration (T1567), collecte d'informations à partir de sources accessibles (T1213) et accès aux données stockées (T1530). | T1486, T1657, T1567, T1213, T1530 | `hxxps://databreaches[.]net/2026/10/04/slate-valley-unified-school-district-voted-not-to-pay-ransom-demand-kairos-likely-to-leak-data/` |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Moyen-Orient, Émirats arabes unis, Arabie saoudite, Iran, États-Unis, Golfe** | Énergie, infrastructures critiques, ports, raffineries, cybersécurité | Guerre hybride et attaques cyber couplées aux frappes militaires contre les infrastructures critiques | Le responsable de la cybersécurité des Émirats arabes unis, Mohamed Al Kuwaiti, a révélé que chaque attaque de missile ou de drone contre les ports, installations énergétiques et raffineries du pays depuis le début de la guerre en Iran a été accompagnée d'une cyberattaque visant la même cible. Le nombre moyen d'attaques numériques a triplé depuis le 28 février, atteignant entre 600 000 et 800 000 par jour. L'Arabie saoudite a signé un accord de coopération en cybersécurité avec le Pakistan. Les menaces touchent les infrastructures critiques et les PME. Les systèmes OT sont particulièrement exposés car supposés isolés mais connectés à Internet. Des hackers iraniens ont accédé à des caméras de sécurité en Israël pour surveiller les troupes et évaluer les dégâts, et ont tenté de compromettre des caméras aux Émirats, Qatar, Bahreïn et Koweït. En juillet, des acteurs affiliés à l'Iran ont exploité des automates programmables pour perturber des infrastructures critiques aux États-Unis. Les gouvernements régionaux partagent du renseignement et se préparent conjointement. | [https://www.wired.me/story/every-iranian-strike-on-uae-ports-and-refineries-was-paired-with-a-cyberattack](https://www.wired.me/story/every-iranian-strike-on-uae-ports-and-refineries-was-paired-with-a-cyberattack)<br>[https://www.reddit.com/r/blueteamsec/comments/1wxkb9z/every_iranian_strike_on_uae_ports_and_refineries/](https://www.reddit.com/r/blueteamsec/comments/1wxkb9z/every_iranian_strike_on_uae_ports_and_refineries/)<br>`hxxps://www[.]wired[.]me/story/every-iranian-strike-on-uae-ports-and-refineries-was-paired-with-a-cyberattack` |
| **Amérique latine, Panama, Argentine, Équateur, Guatemala, Honduras, Pérou, Porto Rico, Venezuela, Chine** | Gouvernement, administration publique, cybersécurité, espionnage | Cyberespionnage aligné sur la Chine et déplacement des cibles vers l'Amérique latine | ESET a documenté le 17 septembre 2026 un nouvel outil nommé SparroWocky utilisé par FamousSparrow, un groupe de cyberespionnage décrit comme aligné sur la Chine. Entre mi-2025 et 2026, 90 % des cibles de FamousSparrow observées par ESET se trouvent en Amérique latine. SparroWocky a été observé contre des entités gouvernementales en Argentine, Équateur, Guatemala, Honduras, Panama, Pérou, Porto Rico et Venezuela. Au Panama, une entité ciblée intervient dans le conflit autour des ports stratégiques de Balboa et Cristóbal. SparroWocky est écrit en C++, ne chiffre pas les données, mais permet de rester dans le système, collecter des informations, parcourir les répertoires, copier, déplacer ou supprimer des fichiers, lancer des commandes, transférer des données, servir de proxy TCP et charger des Beacon Object Files en mémoire. Il prend une capture d'écran toutes les 500 ms et n'envoie que les pixels modifiés. Le groupe est actif depuis au moins 2019, a exploité ProxyLogon en 2021, ciblé des hôtels, gouvernements, organisations internationales, sociétés d'ingénierie et cabinets juridiques. Après une discrétion entre 2022 et 2024, ESET l'a retrouvé en juillet 2024 dans une association financière américaine, avec des liens vers un institut de recherche mexicain et une institution gouvernementale hondurienne. SparroWocky est une famille distincte de SparrowDoor. | [https://librexpression.fr/famoussparrow-migre-en-amerique-latine](https://librexpression.fr/famoussparrow-migre-en-amerique-latine)<br>[https://mastodonapp.uk/@Kimbo106/117383361994505601](https://mastodonapp.uk/@Kimbo106/117383361994505601)<br>`hxxps://librexpression[.]fr/famoussparrow-migre-en-amerique-latine` |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| https://combat.theater/blog/module-stomping/ | Combat Theater | 2026-10-04 | N/A | https://combat.theater/blog/module-stomping/ | L'article décrit la technique de « module stomping », une méthode d'injection de code dans l'espace d'adressage d'une DLL légitime chargée dans un processus. Cette technique est de plus en plus utilisée par les agents C2 modernes car elle est relativement simple à implémenter, permet de contrôler où le code s'exécute et évite certaines caractéristiques mémoire évidentes de l'injection de shellcode traditionnelle. L'article détaille les étapes : sélection d'un processus cible, chargement d'une DLL sacrificielle (via LoadLibrary/LdrLoadDll ou NtCreateSection/NtMapViewOfSection), puis écrasement du code exécutable (souvent à l'AddressOfEntryPoint). Il mentionne les avantages et inconvénients de chaque méthode, notamment les artefacts de chargement détectables (EntryPoint NULL, ImageDll FALSE) et les implications pour la télémétrie défensive. | [https://combat.theater/blog/module-stomping/](https://combat.theater/blog/module-stomping/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Secteur financier / bancaire (Corée du Sud)** | Shinhan Bank, KB Kookmin Bank, Hana Bank, BNK Busan Bank (Corée du Sud) | Données personnelles de clients bancaires (identité, coordonnées, informations de compte selon les systèmes touchés), données de collaborateurs internes, données personnelles de développeurs externes sous-traitants. Les volumes confirmés par établissement sont partiels et les périmètres exacts restent en cours d'investigation. | 25948 | `hxxps://malware[.]news/t/south-korea-s-president-lee-jae-myung-orders-thorough-probe-into-data-breaches-at-local-banks/126119`<br>`hxxps://databreaches[.]net/2026/10/04/south-koreas-president-lee-jae-myung-orders-thorough-probe-into-data-breaches-at-local-banks/`<br>`hxxps://dailytechnow[.]com/south-korean-bank-cyberattacks/` |
| **Construction maritime et services subsea (transport / construction)** | Precon Marine Inc | Aucune donnée confirmée. Exposition potentielle alléguée : documentation de projets, plans d'ingénierie, contrats clients, dossiers financiers et informations sur les employés. | Inconnu | `hxxps://www[.]yazoul[.]net/intel/claim/2026-10-04-precon-marine-ransomware-claim-by-netrunner-oct-2026` |
| **Secteur éducatif (district scolaire public, Vermont, États-Unis)** | Slate Valley Unified School District (Fair Haven, Vermont, États-Unis) | Données personnelles d'élèves (noms, dates de naissance, noms des parents, adresses, téléphones), données liées à l'éducation spécialisée (IEP, plans 504, références Medicaid), dossiers confidentiels protégés par le FERPA, et données personnelles et médicales d'employés. Volume revendiqué : 762 Go dont 647 Go de bases SQL. | 762 | `hxxps://databreaches[.]net/2026/10/04/slate-valley-unified-school-district-voted-not-to-pay-ransom-demand-kairos-likely-to-leak-data/` |
| **Multi-secteurs : médias, pharmaceutique, gouvernemental et défense** | The Japan Times, Novo Nordisk, FBI, Department of Defense, gouvernement australien (revue hebdomadaire) | Non précisé dans les sources disponibles. Les secteurs concernés suggèrent des données rédactionnelles et abonnés (médias), des données de recherche et de propriété intellectuelle (pharma), et des données sensibles gouvernementales et de défense. | Inconnu | `hxxps://youtu[.]be/wD8SegGBBSk`<br>`hxxps://soundcloud[.]com/nickaesp/b2026-10-04` |
| **IoT / domotique / sécurité physique (self-hosted)** | OpenAlarm (documentation de sécurité — aucune fuite de données confirmée) | Aucune donnée compromise. La source traite de la prévention des fuites de clés API et de la limitation de leur impact. | Inconnu | `hxxps://docs[.]openalarm[.]io/guides/authentication/` |
| **Éducation** | Technical University of Denmark (DTU) | Numéros CPR, noms complets, adresses personnelles, photos de profil, emails professionnels, titres de poste, emplacements de bureau, détails d'emploi, noms et coordonnées des proches. | 200000 | `hxxps://cyber[.]netsecops[.]io/articles/technical-university-of-denmark-data-breach-exposes-200000-users/`<br>`hxxps://www[.]rescana[.]com/post/dtubasen-data-breach-at-technical-university-of-denmark-dtu-exposes-sensitive-information-of-200-000-users`<br>`hxxps://beyondmachines[.]net/event_details/technical-university-of-denmark-data-breach-impacts-200000-users-9-o-7-w-l/gD2P6Ple2L` |
| **Fabrication (échangeurs de chaleur)** | T.RAD North America | Enregistrements clients et fournisseurs, dessins techniques, données financières, informations personnelles d'employés (PII). | Inconnu | `hxxps://go[.]darkwebsonar[.]io/marlanwg-mastodon` |
| **Voyage** | Wakacje.pl | Détails de passeport, noms complets, adresses email, numéros de téléphone, adresses personnelles, dates de naissance. | Inconnu | `hxxps://beyondmachines[.]net/event_details/wakacje-pl-data-breach-exposes-customer-passport-details-and-personal-information-f-3-0-w-t/gD2P6Ple2L` |
| **Banque** | Welcome Savings Bank | Noms d'entreprise, noms de contacts corporatifs, adresses email, numéros de téléphone. | 2200 | `hxxps://beyondmachines[.]net/event_details/welcome-savings-bank-confirms-data-breach-affecting-2200-corporate-clients-r-9-5-h-x/gD2P6Ple2L` |
| **Finance (crédit auto)** | Hyundai Capital | Numéros de résident (13 chiffres), identifiants internes d'agents et de recruteurs, numéros d'enregistrement de la Korea Credit Finance Association, numéros de téléphone mobile, noms complets, adresses email. | 146 | `hxxps://beyondmachines[.]net/event_details/hyundai-capital-data-breach-exposes-national-id-numbers-of-146-loan-agents-o-d-k-3-1/gD2P6Ple2L` |
| **Éducation** | Frontline Education | Données d'employés de districts scolaires (non spécifiées). | Inconnu | `hxxps://www[.]bleepingcomputer[.]com/news/security/frontline-education-data-breach-impacts-school-district-employees/` |
| **Gouvernement / Défense** | Pentagon / Defense Manpower Data Center (DMDC) | Informations personnelles sensibles de plus de 3 millions de personnes (données de personnel du DMDC). | 3000000 | [https://cybersecuritynews.com/pentagon-data-breach/](https://cybersecuritynews.com/pentagon-data-breach/)<br>[https://fed.brid.gy/r/https://bsky.app/profile/did:plc:7hc3ntwii55gbipddmecsn47/post/3mwzx4knu4c2q](https://fed.brid.gy/r/https://bsky.app/profile/did:plc:7hc3ntwii55gbipddmecsn47/post/3mwzx4knu4c2q) |
| **Santé** | Hospital de la Santa Creu i Sant Pau | Données médicales et de recherche potentiellement exposées (non confirmé, aucune catégorie ni volume précisé). | Inconnu | [https://www.yazoul.net/intel/claim/2026-10-03-hospital-de-sant-pau-ransomware-claim-by-thegentlemen-oct-2026](https://www.yazoul.net/intel/claim/2026-10-03-hospital-de-sant-pau-ransomware-claim-by-thegentlemen-oct-2026) |
| **Multi-secteurs / Application de la loi** | FBI (portail apply.fbijobs[.]gov) / organisations victimes de ShinyHunters | Environ 3 téraoctets de données sensibles du portail FBI apply.fbijobs[.]gov ; données de plus de 140 organisations victimes. | Inconnu | [https://thehackernews.com/2026/10/shinyhunters-suspect-rey-reportedly.html](https://thehackernews.com/2026/10/shinyhunters-suspect-rey-reportedly.html) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-90970** | 9.9 | N/A | FALSE | GitLab AI Gateway | Vulnérabilité critique (compromission du gateway IA, interception de prompts et de données LLM) | Compromission du gateway IA, vol de secrets et de clés API, interception et altération des échanges avec les LLM, exposition de données internes sensibles. Le vecteur est exploitable à distance et le score CVSS 9.9 en fait une priorité de remédiation immédiate. | None | Appliquer sans délai le correctif GitLab. En attendant, restreindre l'exposition réseau du gateway, révoquer/régénérer les secrets et clés API, et surveiller les accès anormaux. Ne pas reporter le patch à la prochaine fenêtre de maintenance. | [https://securityaffairs.com/200367/ai/security-affairs-ai-cybersecurity-newsletter-round-2.html](https://securityaffairs.com/200367/ai/security-affairs-ai-cybersecurity-newsletter-round-2.html)<br>[https://securityaffairs.com/200354/security/security-affairs-malware-newsletter-round-117.html](https://securityaffairs.com/200354/security/security-affairs-malware-newsletter-round-117.html)<br>[https://securityaffairs.com/200338/cyber-crime/shinyhunters-suspect-detained-in-jordan-helps-fbi-track-down-the-group.html](https://securityaffairs.com/200338/cyber-crime/shinyhunters-suspect-detained-in-jordan-helps-fbi-track-down-the-group.html)<br>[https://securityaffairs.com/200326/breaking-news/security-affairs-newsletter-round-598-by-pierluigi-paganini-international-edition.html](https://securityaffairs.com/200326/breaking-news/security-affairs-newsletter-round-598-by-pierluigi-paganini-international-edition.html)<br>[https://securityaffairs.com/200304/malware/warlock-ransomware-still-exploits-year-old-sharepoint-flaws-to-hit-critical-infrastructure.html](https://securityaffairs.com/200304/malware/warlock-ransomware-still-exploits-year-old-sharepoint-flaws-to-hit-critical-infrastructure.html)<br>[https://theperimetersite.com/report/328](https://theperimetersite.com/report/328)<br>[https://infosec.exchange/@theperimetersite/117383634542061141](https://infosec.exchange/@theperimetersite/117383634542061141)<br>[https://theperimetersite.com/report/327](https://theperimetersite.com/report/327)<br>[https://infosec.exchange/@theperimetersite/117382435485855275](https://infosec.exchange/@theperimetersite/117382435485855275) |
| **CVE-2026-86950** | N/A | N/A | FALSE | Apple CoreGraphics (macOS, iOS, iPadOS) | Zero-day exploité dans des attaques ciblées sophistiquées | Exécution de code arbitraire sur les terminaux Apple, compromission de postes ciblés, potentielle exfiltration de données. Le caractère zero-day et l'existence d'un PoC public accroissent l'urgence de la remédiation. | Active | Appliquer sans délai les mises à jour Apple corrigeant CVE-2026-86950. Restreindre l'ouverture de contenus non sollicités, surveiller les terminaux et isoler tout poste présentant des signes de compromission. | [https://securityaffairs.com/200367/ai/security-affairs-ai-cybersecurity-newsletter-round-2.html](https://securityaffairs.com/200367/ai/security-affairs-ai-cybersecurity-newsletter-round-2.html)<br>[https://securityaffairs.com/200354/security/security-affairs-malware-newsletter-round-117.html](https://securityaffairs.com/200354/security/security-affairs-malware-newsletter-round-117.html)<br>[https://securityaffairs.com/200338/cyber-crime/shinyhunters-suspect-detained-in-jordan-helps-fbi-track-down-the-group.html](https://securityaffairs.com/200338/cyber-crime/shinyhunters-suspect-detained-in-jordan-helps-fbi-track-down-the-group.html)<br>[https://securityaffairs.com/200326/breaking-news/security-affairs-newsletter-round-598-by-pierluigi-paganini-international-edition.html](https://securityaffairs.com/200326/breaking-news/security-affairs-newsletter-round-598-by-pierluigi-paganini-international-edition.html)<br>[https://securityaffairs.com/200304/malware/warlock-ransomware-still-exploits-year-old-sharepoint-flaws-to-hit-critical-infrastructure.html](https://securityaffairs.com/200304/malware/warlock-ransomware-still-exploits-year-old-sharepoint-flaws-to-hit-critical-infrastructure.html) |
| **CVE-2026-105222** | 9.1 | N/A | FALSE | Package Laravel alexpechkarev/google-maps jusqu'à la version 12.16 | Validation de certificat incorrecte (CWE-295) - vérification TLS désactivée par défaut | Interception des requêtes Google Maps, vol de la clé API exposée en clair dans l'URL, altération des réponses renvoyées à l'application. Score CVSS 4.0 de 9.1 (critique) et CVSS 3.1 de 7.4 (élevé). Exploitable à distance. | None | Configurer ssl_verify_peer à TRUE, mettre à jour le package vers une version corrigée si disponible, révoquer et régénérer les clés API, et vérifier l'intégrité des clés et des requêtes. | [https://cvefeed.io/vuln/detail/CVE-2026-105222](https://cvefeed.io/vuln/detail/CVE-2026-105222) |
| **CVE-2026-88779** | 8.7 | N/A | TRUE | Citrix NetScaler ADC (ex-Citrix ADC) et Citrix NetScaler Gateway (ex-Citrix Gateway), y compris les déploiements Secure Private Access Hybrid | Débordement mémoire / corruption mémoire (CWE-119) entraînant un déni de service | Un attaquant distant non authentifié peut provoquer un déni de service sur les instances NetScaler ADC/Gateway. Des exploitations répétées peuvent entraîner l'indisponibilité complète du service, impactant l'accès distant des employés, la publication d'applications et la disponibilité des services exposés. L'impact opérationnel est élevé pour les organisations dépendant de NetScaler pour l'accès distant et la répartition de charge. | Active | Mettre à jour vers les versions corrigées : NetScaler ADC 14.1-73.41 ou ultérieur, 13.1-64.28 ou ultérieur, ADC FIPS 14.1-73.41 FIPS ou ultérieur, 13.1-37.282 ou ultérieur ; NetScaler Gateway 14.1-73.41 ou ultérieur, 13.1-64.28 ou ultérieur. Appliquer les workarounds Citrix en attendant. Restreindre l'exposition Internet des instances non patchées et suivre les directives CISA BOD 26-04. | [https://cvefeed.io/vuln/detail/CVE-2026-88779](https://cvefeed.io/vuln/detail/CVE-2026-88779)<br>[https://www.security.nl/posting/955844/Citrix+waarschuwt+voor+actief+misbruik+van+nieuw+beveiligingslek?channel=rss](https://www.security.nl/posting/955844/Citrix+waarschuwt+voor+actief+misbruik+van+nieuw+beveiligingslek?channel=rss)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697174](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697174)<br>[https://infosec.exchange/@secdb/117384650420194905](https://infosec.exchange/@secdb/117384650420194905) |
| **CVE-2026-105213** | 8.8 | N/A | FALSE | ZITADEL 4.x avant 4.17.1 | Contournement d'authentification (CWE-287) via Login V2 pour organisations désactivées | La vulnérabilité contourne le contrôle administratif de désactivation d'organisation, souvent utilisé comme mesure d'offboarding ou de confinement. Les utilisateurs d'organisations désactivées conservent un accès non autorisé, ce qui peut permettre la persistance d'accès après révocation, l'extension de sessions et l'accès à des ressources protégées par ZITADEL. | None | Mettre à jour ZITADEL vers la version 4.17.1 ou ultérieure afin d'appliquer la vérification de l'état d'inactivité de l'organisation lors de l'authentification. Vérifier que les états d'organisation et d'utilisateur sont contrôlés lors du login. Révoquer les sessions et jetons des utilisateurs d'organisations désactivées. | [https://cvefeed.io/vuln/detail/CVE-2026-105213](https://cvefeed.io/vuln/detail/CVE-2026-105213)<br>[https://www.valtersit.com/cve/CVE-2026-105213/](https://www.valtersit.com/cve/CVE-2026-105213/) |
| **CVE-2026-105221** | 9.1 | N/A | FALSE | RubyGem gist avant 6.1.0 | Validation de certificat incorrecte (CWE-295) - désactivation de la vérification TLS | Un attaquant positionné sur le chemin réseau peut intercepter et modifier le trafic HTTPS entre le client et l'API GitHub, compromettant les tokens OAuth et les identifiants de connexion. Cela permet la lecture et la modification des gists de la victime, ainsi que l'accès potentiel à d'autres ressources GitHub liées au compte compromis. | None | Mettre à jour le RubyGem gist vers la version 6.1.0 ou ultérieure pour rétablir la validation correcte des certificats. Vérifier que le trafic HTTPS est correctement validé et protéger les tokens OAuth et identifiants de connexion. Révoquer les jetons potentiellement exposés. | [https://cvefeed.io/vuln/detail/CVE-2026-105221](https://cvefeed.io/vuln/detail/CVE-2026-105221) |
| **CVE-2026-105220** | 8.5 | N/A | FALSE | Twine 2 Desktop jusqu'à la version 2.12.0 | Cross-Site Scripting (CWE-79) menant à une exécution de code arbitraire | Exécution de code arbitraire sur le poste de la victime avec les droits de l'utilisateur, permettant vol de données, installation de malware ou mouvement latéral. | Theoretical | Mettre à jour Twine vers une version corrigeant la XSS dans importStories(), éviter d'importer des fichiers de story non fiables et valider rigoureusement le contenu importé. | [https://cvefeed.io/vuln/detail/CVE-2026-105220](https://cvefeed.io/vuln/detail/CVE-2026-105220)<br>[https://www.vulncheck.com/advisories/twine-2-desktop-through-2.12.0-arbitrary-code-execution-via-imported-story-files](https://www.vulncheck.com/advisories/twine-2-desktop-through-2.12.0-arbitrary-code-execution-via-imported-story-files) |
| **CVE-2026-105219** | 8.7 | N/A | FALSE | Mammoth.js 1.3.0 avant 1.12.3 | Regular Expression Denial of Service (CWE-1333) | Déni de service : blocage du service Node.js traitant les documents, indisponibilité applicative et consommation excessive de CPU. | Theoretical | Mettre à jour Mammoth.js vers la version 1.12.3 ou supérieure, assainir les entrées utilisateur et surveiller l'utilisation des ressources système. | [https://cvefeed.io/vuln/detail/CVE-2026-105219](https://cvefeed.io/vuln/detail/CVE-2026-105219)<br>[https://www.vulncheck.com/advisories/mammoth-js-1.3.0-before-1.12.3-redos-via-style-map-tokeniser](https://www.vulncheck.com/advisories/mammoth-js-1.3.0-before-1.12.3-redos-via-style-map-tokeniser) |
| **CVE-2026-105218** | 9.1 | N/A | FALSE | gopay avant 1.5.119 | Validation de certificat incorrecte (CWE-295) | Interception et modification du trafic de paiement, vol d'identifiants marchands et de données de transaction, fraude financière potentielle. | Theoretical | Mettre à jour gopay vers la version 1.5.119 ou supérieure et s'assurer que la validation des certificats TLS est correctement configurée dans defaultClient(). | [https://cvefeed.io/vuln/detail/CVE-2026-105218](https://cvefeed.io/vuln/detail/CVE-2026-105218)<br>[https://www.vulncheck.com/advisories/gopay-before-1.5.119-disabled-tls-certificate-verification-in-xhttp-client](https://www.vulncheck.com/advisories/gopay-before-1.5.119-disabled-tls-certificate-verification-in-xhttp-client) |
| **CVE-2026-105216** | 9.1 | N/A | FALSE | go-micro avant 6.0.0 | Validation de certificat incorrecte (CWE-295) | Interception et modification des communications inter-services, vol de jetons d'authentification et d'identifiants, compromission potentielle de l'ensemble du maillage de microservices. | Theoretical | Mettre à jour go-micro vers la version 6.0.0 ou supérieure, configurer TLS pour valider les certificats et revoir toutes les configurations TLS. | [https://cvefeed.io/vuln/detail/CVE-2026-105216](https://cvefeed.io/vuln/detail/CVE-2026-105216)<br>[https://www.vulncheck.com/advisories/go-micro-before-6.0.0-disabled-tls-certificate-verification-via-tls-config-helper](https://www.vulncheck.com/advisories/go-micro-before-6.0.0-disabled-tls-certificate-verification-via-tls-config-helper) |
| **CVE-2026-105089** | 9.3 | N/A | FALSE | WWBN AVideo jusqu'à la version 29.2.0 | Cross-Site Scripting stockée (CWE-79) | Exécution de JavaScript arbitraire dans le navigateur des victimes, vol de sessions, redirection vers des sites malveillants ou actions non autorisées au nom de l'utilisateur. | Theoretical | Assainir toutes les URLs de trailer fournies par les utilisateurs, garantir un encodage de sortie empêchant l'exécution de scripts, mettre à jour AVideo et revoir la logique de rendu des templates et playlists. | [https://cvefeed.io/vuln/detail/CVE-2026-105089](https://cvefeed.io/vuln/detail/CVE-2026-105089)<br>[https://www.vulncheck.com/advisories/wwbn-avideo-through-29.2.0-stored-xss-via-trailer1-in-youphpflix2-templates](https://www.vulncheck.com/advisories/wwbn-avideo-through-29.2.0-stored-xss-via-trailer1-in-youphpflix2-templates) |
| **CVE-2026-105086** | 9.3 | N/A | FALSE | WWBN AVideo 12.4 à 29.2.0 | Cross-Site Scripting stockée (CWE-79) | Exécution de JavaScript arbitraire dans le navigateur des victimes, vol de sessions, redirection vers des sites malveillants ou actions non autorisées au nom de l'utilisateur. | Theoretical | Mettre à jour AVideo vers une version corrigée, assainir tous les titres de vidéos soumis par les utilisateurs et garantir un encodage de sortie correct pour toutes les données affichées. | [https://cvefeed.io/vuln/detail/CVE-2026-105086](https://cvefeed.io/vuln/detail/CVE-2026-105086)<br>[https://www.vulncheck.com/advisories/wwbn-avideo-12.4-through-29.2.0-stored-xss-via-double-encoded-video-title](https://www.vulncheck.com/advisories/wwbn-avideo-12.4-through-29.2.0-stored-xss-via-double-encoded-video-title) |
| **CVE-2026-105215** | 9.3 | N/A | FALSE | ZITADEL avant 3.4.14 et 4.x avant 4.16.2 | Contournement d'authentification par usurpation (CWE-290) | Pré-hijacking de compte : un attaquant peut lier un compte à l'identité externe d'une victime et prendre le contrôle de ce compte lors de la première connexion légitime de la victime. | Theoretical | Mettre à jour ZITADEL vers la version 3.4.14 ou 4.16.2. | [https://cvefeed.io/vuln/detail/CVE-2026-105215](https://cvefeed.io/vuln/detail/CVE-2026-105215)<br>[https://www.vulncheck.com/advisories/zitadel-before-4.16.2-account-pre-hijacking-via-forged-external-idp-callback](https://www.vulncheck.com/advisories/zitadel-before-4.16.2-account-pre-hijacking-via-forged-external-idp-callback) |
| **CVE-2026-105212** | 8.7 | N/A | FALSE | ZITADEL 3.x avant 3.4.14 et 4.x avant 4.16.2 | Authentification incorrecte (CWE-287) | Prise de contrôle de compte : un attaquant peut se connecter en tant que n'importe quel utilisateur dont il connaît le nom de connexion, en contournant les mots de passe et le MFA. | Theoretical | Mettre à jour ZITADEL vers la version 3.4.14 ou 4.16.2. | [https://cvefeed.io/vuln/detail/CVE-2026-105212](https://cvefeed.io/vuln/detail/CVE-2026-105212)<br>[https://www.vulncheck.com/advisories/zitadel-before-3.4.14-and-4.16.2-account-takeover-via-passkey-enrollment](https://www.vulncheck.com/advisories/zitadel-before-3.4.14-and-4.16.2-account-takeover-via-passkey-enrollment) |
| **CVE-2026-105211** | N/A | N/A | FALSE | ZITADEL (Login V2) versions antérieures à 4.17.1 | Contournement d'authentification (Authentication Bypass) | Compromission de comptes utilisateurs et administrateurs, accès non autorisé aux applications fédérées et élévation de privilèges au sein de l'instance ZITADEL. | Theoretical | Mettre à jour ZITADEL vers la version 4.17.1 ou supérieure. En attendant, désactiver Login V2 ou restreindre l'exposition réseau de l'interface d'authentification et surveiller les journaux OTP. | [https://cvefeed.io/vuln/detail/CVE-2026-105211](https://cvefeed.io/vuln/detail/CVE-2026-105211) |
| **CVE-2026-105210** | 8.8 | N/A | FALSE | ZITADEL 3.x < 3.4.15 et 4.x < 4.17.1 (Login V1) | Authentification manquante (CWE-287) | Prise de contrôle de comptes via l'enrôlement de facteurs MFA malveillants, contournement de la MFA et énumération d'utilisateurs. | Theoretical | Mettre à jour ZITADEL vers 3.4.15 ou 4.17.1. Vérifier le facteur primaire avant tout enrôlement de second facteur et restreindre l'accès à Login V1. | [https://cvefeed.io/vuln/detail/CVE-2026-105210](https://cvefeed.io/vuln/detail/CVE-2026-105210) |
| **CVE-2026-105209** | 9.6 | N/A | FALSE | ZITADEL 3.x < 3.4.15 et 4.x < 4.17.1 | Autorisation manquante (CWE-862) | Prise de contrôle de comptes inter-organisations, usurpation d'identité et accès non autorisé aux ressources d'autres tenants. | Theoretical | Mettre à jour ZITADEL vers 3.4.15 ou 4.17.1. Valider le contexte d'organisation pour les codes d'enrôlement et restreindre les permissions user-write. | [https://cvefeed.io/vuln/detail/CVE-2026-105209](https://cvefeed.io/vuln/detail/CVE-2026-105209) |
| **CVE-2026-105208** | 8.7 | N/A | FALSE | ZITADEL 4.x < 4.17.3 et 3.x <= 3.4.15 | Chiffrement sans contrôle d'intégrité (CWE-649) | Vol de jetons IdP, détournement de session et prise de contrôle de comptes via des fournisseurs d'identité externes. | Theoretical | Mettre à jour ZITADEL vers 4.17.3 ou 3.4.15. Utiliser un chiffrement authentifié avec contrôle d'intégrité pour les jetons d'intention IdP. | [https://cvefeed.io/vuln/detail/CVE-2026-105208](https://cvefeed.io/vuln/detail/CVE-2026-105208) |
| **CVE-2026-105207** | 9.8 | N/A | FALSE | ZITADEL 3.0.0 à 3.4.15 et 4.0.0 < 4.17.3 | Authentification manquante pour fonction critique (CWE-306) | Prise de contrôle de comptes, usurpation d'identité et accès non autorisé aux applications fédérées. | Theoretical | Mettre à jour ZITADEL vers 4.17.3. Vérifier le facteur primaire et les permissions de l'appelant pour toute liaison IdP et restreindre l'accès à l'API User Service V2. | [https://cvefeed.io/vuln/detail/CVE-2026-105207](https://cvefeed.io/vuln/detail/CVE-2026-105207) |
| **CVE-2026-103355** | 9.3 | N/A | FALSE | WordPress Unlimited Elements For Elementor (Free Widgets, Addons, Templates) <= 2.0.20 | Injection SQL (CWE-89) | Exfiltration de données de la base de données (identifiants, contenus, données utilisateurs) et potentielle compromission complète du site. | Theoretical | Mettre à jour le plugin vers une version corrigée. Appliquer les correctifs de sécurité de l'éditeur et valider la sanitisation de toutes les requêtes SQL. | [https://cvefeed.io/vuln/detail/CVE-2026-103355](https://cvefeed.io/vuln/detail/CVE-2026-103355) |
| **CVE-2026-105135** | N/A | N/A | FALSE | InternLM MindSearch (Planner Agent, graph.py) | Injection de code (Code Injection) | Exécution de code arbitraire sur le serveur hébergeant l'agent, compromission de l'environnement d'exécution et accès non autorisé aux données traitées. | Theoretical | Appliquer le correctif de l'éditeur ou mettre à jour MindSearch. Restreindre les permissions d'exécution et valider les entrées avant tout appel à ExecutionAction.run. | [https://cvefeed.io/vuln/detail/CVE-2026-105135](https://cvefeed.io/vuln/detail/CVE-2026-105135) |
| **CVE-2026-105134** | 10.0 | N/A | FALSE | Ahsay AhsayCBS <= 10.3.2 (composant Replication Receiver) | Injection de commande OS (CWE-78) | Exécution de commandes arbitraires sur le serveur, compromission complète de l'hôte et accès aux données de sauvegarde. | Active | Mettre à jour Ahsay AhsayCBS vers la version 10.3.4. Appliquer les mises à jour du composant Replication Receiver et restreindre son exposition réseau. | [https://cvefeed.io/vuln/detail/CVE-2026-105134](https://cvefeed.io/vuln/detail/CVE-2026-105134) |
| **CVE-2026-96940** | N/A | N/A | FALSE | Microsoft Exchange Server SE, Exchange Server 2019 et Exchange Server 2016 (on-premises) | Élévation de privilèges permettant l'accès aux boîtes aux lettres | Compromission de la confidentialité des communications : lecture de l'ensemble des courriels et pièces jointes des utilisateurs de l'organisation, avec risque d'exfiltration de données sensibles et d'escalade vers d'autres systèmes via les informations collectées. | Theoretical | Appliquer sans délai les mises à jour de sécurité publiées le 2 octobre 2026 sur Exchange Server SE, 2019 et 2016. Vérifier que les instances Exchange Online sont bien à jour. En attendant le patch, restreindre les accès authentifiés non indispensables, surveiller les journaux d'accès aux boîtes aux lettres et appliquer le principe du moindre privilège sur les comptes Exchange. | [https://www.security.nl/posting/955847/Microsoft+verwacht+misbruik+van+Exchange-lek+dat+toegang+tot+mailboxes+geeft?channel=rss](https://www.security.nl/posting/955847/Microsoft+verwacht+misbruik+van+Exchange-lek+dat+toegang+tot+mailboxes+geeft?channel=rss) |
| **CVE-2026-102437** | N/A | N/A | FALSE | DeepSeek-Reasonix Studio (client Git desktop pour assistants de codage IA) et DeepSeek Reasonix npm | Exécution de commandes à distance via empoisonnement de configuration Git (ConfigPoisoning) | Exécution de code arbitraire sur le poste du développeur avec les privilèges de celui-ci, pouvant mener au vol d'identifiants, à la compromission de la chaîne de développement et à la propagation vers d'autres dépôts ou systèmes internes. | Theoretical | Mettre à jour vers DeepSeek-Reasonix Studio 2.21.0 ou DeepSeek Reasonix npm 1.39.3. Pour les outils s'interfaçant avec git, ne pas se limiter au correctif d'une clé : surcharger toutes les clés pertinentes à chaque appel ou éviter d'invoquer les mécanismes de filtre et textconv de git. Vérifier les fichiers .git/config et .gitattributes des dépôts clonés depuis des sources non fiables. | [https://about.gitlab.com/blog/deepseek-reasonix-vulnerability-discovered/](https://about.gitlab.com/blog/deepseek-reasonix-vulnerability-discovered/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="curiosites-des-chaines-user-agent-dim-4-oct"></div>

## Curiosités des chaînes User-Agent, (dim. 4 oct.)

### Résumé

L'auteur analyse les User-Agent Strings (UAS) observés dans les logs de ses honeypots. Il relève des UAS revendiquant explicitement un scan « autorisé », des UAS répétés signalant une compromission déjà subie, ainsi que des UAS contenant des URL ou adresses e-mail de contact des personnes opérant les scanners (dont une adresse biélorusse déjà évoquée). De nombreuses variantes de masscan sont présentes, y compris une variante « KGB ». Le mot « scan » est fréquemment inclus dans les UAS, certains contenant des jeux de mots ou des messages de dénigrement. Certains scanners utilisent des listes complètes d'UAS en changeant de chaîne à chaque requête, sans assainir ces listes : des lignes de séparation issues d'un dépôt public d'UAS sont ainsi envoyées telles quelles comme UAS. Des tentatives d'exploitation du parsing d'UAS sont également observées, notamment des charges Shellshock vieilles de plus de dix ans. Enfin, une requête ciblant des serveurs diffusant des données de correction GPS via le protocole NTRIP (avec en-tête NTRIP inclus) est signalée.

---

### Analyse opérationnelle

Les UAS constituent une source de télémétrie à faible coût pour détecter la reconnaissance à grande échelle. Les équipes SOC peuvent exploiter ces observations pour : (1) construire des règles de détection sur les UAS contenant des mots-clés de scan ou des charges d'exploitation ; (2) identifier les scanners utilisant des listes d'UAS rotatives, qui contournent les blocages naïfs basés sur une chaîne unique ; (3) détecter les tentatives Shellshock encore actives malgré l'ancienneté de la vulnérabilité, ce qui implique de vérifier que les services exposés ne sont pas vulnérables ; (4) surveiller les protocoles industriels/spécialisés (NTRIP) exposés sur Internet, souvent oubliés dans les inventaires. La présence d'adresses de contact dans les UAS facilite l'attribution et la notification, mais ne doit pas conduire à une confiance implicite. Les UAS ne doivent jamais servir de mécanisme d'authentification ou d'autorisation.

---

### Implications stratégiques

Le bruit de fond du scanning Internet reste constant et industrialisé : toute organisation exposant des services publics est scannée en continu, indépendamment de sa taille ou de son secteur. L'usage de listes d'UAS publiques non assainies illustre la faible sophistication d'une partie des acteurs, mais aussi la difficulté à filtrer sur des critères triviaux. La persistance de charges Shellshock et le ciblage de protocoles de niche (NTRIP, diffusion de corrections GPS) rappellent que les actifs OT/spécialisés exposés constituent une surface d'attaque sous-estimée. Décisionnellement, cela plaide pour une réduction systématique de la surface exposée et une politique de filtrage fondée sur le comportement plutôt que sur l'identité déclarée du client.

---

### Recommandations

* Ne jamais accorder de confiance à un User-Agent String : il est trivialement falsifiable.
* Mettre en place des règles WAF/IPS sur les UAS contenant des charges d'exploitation (Shellshock, injection de commande).
* Inventorier et restreindre l'exposition Internet des protocoles spécialisés (NTRIP, OT, IoT).
* Corréler les UAS rotatifs avec les volumes de requêtes pour détecter les scanners à liste.
* Exploiter les adresses de contact présentes dans les UAS pour la notification et le renseignement, sans en tirer de conclusion d'autorisation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer et maintenir des honeypots/sensors exposés sur Internet pour capter les User-Agent Strings et les en-têtes anormaux.
* Normaliser la collecte des logs HTTP (UAS, URI, en-têtes) dans le SIEM avec rétention suffisante pour l'analyse de tendance.
* Constituer une liste de référence des UAS légitimes par application métier afin de réduire les faux positifs.
* Documenter les règles WAF/IPS couvrant les injections dans les en-têtes (Shellshock, traversée de chemin, injection de commande).

#### Phase 2 — Détection et analyse

* Alerter sur les UAS contenant des mots-clés de scan (scan, masscan, nmap, zgrab) ou des adresses e-mail/URL de contact.
* Détecter les UAS contenant des charges exploitables (parenthèses Shellshock, séquences de commandes, séparateurs de listes non assainis).
* Surveiller les requêtes portant des en-têtes protocolaires inhabituels (ex. NTRIP) sur des services non concernés.
* Corréler les UAS identiques ou rotatifs provenant d'une même source pour identifier les scanners à liste d'UAS.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer au niveau WAF/pare-feu les sources à fort volume de scan après qualification.
* Rejeter les requêtes dont l'UAS contient des charges d'exploitation connues et journaliser la tentative.
* Isoler tout service exposé ayant répondu favorablement à une tentative d'exploitation détectée.
* Appliquer un rate-limiting sur les endpoints publics les plus scannés.

#### Phase 4 — Activités post-incident

* Mettre à jour les signatures WAF/IPS à partir des UAS et charges observés.
* Réduire la surface exposée : recensement des services publics, décommissionnement des services obsolètes.
* Restituer les tendances de scan à la direction pour arbitrer les priorités de durcissement.
* Revoir la politique de journalisation et la qualité des données de honeypot.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement dans les logs les UAS marqués comme scanners ou contenant des charges Shellshock.
* Identifier les actifs ayant répondu en 200 à des requêtes de scan et vérifier l'absence de compromission.
* Cartographier les sources récurrentes (ASN, plages IP) et leur évolution dans le temps.
* Comparer les UAS observés aux campagnes de scanning connues pour attribuer les activités.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595** | Active Scanning : balayages massifs observés dans les logs du honeypot (variantes masscan, UAS 'scan'). |
| **T1190** | Exploit Public-Facing Application : tentatives Shellshock injectées dans les chaînes User-Agent. |
| **T1592** | Gather Victim Host Information : collecte d'informations via requêtes NTRIP et en-têtes spécifiques. |

---

### Sources

* [https://isc.sans.edu/diary/rss/33394](https://isc.sans.edu/diary/rss/33394)


---

<div id="conseil-de-securite-auditez-vos-dependances-transitives-les-applications-modernes-sont-construites-sur-des-couches-de-bibliotheques-meme-si-vous-maintenez-a-jour-vos-imports-directs-les-dependances-de-dependances-restent-souvent-non-corrigees-les-attaquants-ciblent-frequemment-ces-couches-plus-profondes-pour-rester-sous-le-radar-action-utilisez-des-outils-sca-pour-visualiser-lintegralite-de-votre-arbre-de-dependances-et-configurer-des-alertes-pour-les-vulnerabilites-dans-chaque-couche-gardez-une-longueur-davance-sur-les-menaces-httpscvedatabasecom-cybersecurity-infosec-cve-appsec"></div>

## Conseil de sécurité : auditez vos dépendances transitives ! 🛡️ Les applications modernes sont construites sur des couches de bibliothèques. Même si vous maintenez à jour vos imports directs, les « dépendances de dépendances » restent souvent non corrigées. Les attaquants ciblent fréquemment ces couches plus profondes pour rester sous le radar. Action : utilisez des outils SCA pour visualiser l’intégralité de votre arbre de dépendances et configurer des alertes pour les vulnérabilités dans chaque couche. Gardez une longueur d’avance sur les menaces : https://cvedatabase.com #CyberSecurity #InfoSec #CVE #AppSec

### Résumé

Le message recommande d'auditer les dépendances transitives des applications modernes : si les imports directs sont souvent maintenus à jour, les « dépendances de dépendances » restent fréquemment non patchées et sont ciblées par les attaquants pour rester discrètes. L'action préconisée est d'utiliser des outils SCA (Software Composition Analysis) pour visualiser l'arbre complet des dépendances et configurer des alertes sur les vulnérabilités à chaque niveau. Le message renvoie vers cvedatabase.com, qui agrège les données NVD en direct avec CISA KEV, les prédictions d'exploitation EPSS et des conseils de remédiation, et propose des alertes e-mail gratuites sur les nouvelles CVE. La page liste des CVE « tendance » sur 7/30/90 jours, dont plusieurs avis Cisco Catalyst SD-WAN Manager (CVE-2026-20122, CVE-2026-20133, CVE-2026-20127 critique, CVE-2026-20128, CVE-2026-20182 critique), une use-after-free dans Dawn/Google Chrome (CVE-2026-5281), une exposition d'informations dans Desktop Windows Manager (CVE-2026-20805), une XSS dans Zimbra Collaboration (CVE-2025-48700), une élévation de privilèges dans Microsoft Defender (CVE-2026-33825), une RCE dans n8n (CVE-2026-21858), une RCE dans Crawl4AI (CVE-2026-26216), une vulnérabilité BIG-IP APM (CVE-2025-53521) et une injection de code dans Ivanti Endpoint.

---

### Analyse opérationnelle

Le risque principal réside dans l'invisibilité des dépendances transitives : un composant vulnérable peut être présent sans être déclaré dans le manifeste de premier niveau. Les équipes doivent donc instrumenter la CI/CD avec un SCA couvrant l'arbre complet et bloquer les builds introduisant des CVE critiques. La priorisation doit combiner CVSS, présence dans CISA KEV (exploitation avérée) et score EPSS (probabilité d'exploitation), afin d'éviter la saturation par les correctifs. Les CVE listées comme tendance concernent des composants largement déployés (SD-WAN, navigateurs, messagerie, plateformes d'automatisation, appliances VPN/accès distant), ce qui implique des fenêtres d'exposition importantes si la veille n'est pas automatisée. La détection doit aussi couvrir les tentatives d'exploitation sur les composants exposés, pas seulement la remédiation.

---

### Implications stratégiques

La dépendance aux bibliothèques tierces est devenue un risque de chaîne d'approvisionnement structurant : une vulnérabilité dans une couche profonde se propage à des centaines d'applications et de clients. Les organisations doivent traiter la gestion des dépendances comme un enjeu de gouvernance (SBOM, contractualisation avec les fournisseurs, exigences de transparence) et non comme une simple tâche de patch management. La concentration des CVE tendance sur des équipements réseau et de sécurité (SD-WAN, BIG-IP, Ivanti) souligne que les appliances périphériques restent la cible privilégiée des attaquants, avec un impact direct sur la continuité d'activité.

---

### Recommandations

* Déployer un SCA couvrant l'intégralité de l'arbre de dépendances, y compris les dépendances transitives.
* Générer un SBOM par application et l'intégrer au processus de build.
* Prioriser les correctifs via le croisement CVSS / CISA KEV / EPSS plutôt que le seul score CVSS.
* Bloquer en CI/CD l'introduction de dépendances présentant une CVE critique non traitée.
* Automatiser les alertes sur les nouvelles CVE affectant les composants du parc.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer un outil SCA couvrant l'ensemble de l'arbre de dépendances, y compris les dépendances transitives.
* Générer et maintenir un SBOM par application, avec versionnage et traçabilité des composants.
* Mettre en place une veille CVE automatisée (NVD, CISA KEV, EPSS) avec alertes par e-mail ou webhook.
* Définir une politique de correctifs avec des SLA différenciés selon la criticité CVSS, l'exploitation active (KEV) et le score EPSS.

#### Phase 2 — Détection et analyse

* Alerter dès qu'une CVE affectant une dépendance directe ou transitive est publiée ou passe en exploitation active.
* Prioriser les alertes en croisant CVSS, présence dans CISA KEV et probabilité d'exploitation EPSS.
* Détecter les composants obsolètes ou en fin de support dans l'arbre de dépendances.
* Surveiller les tentatives d'exploitation des composants exposés identifiés comme vulnérables.

#### Phase 3 — Confinement, éradication et récupération

* Isoler ou restreindre l'accès aux applications exposant un composant critique non patchable à court terme.
* Appliquer des règles WAF/IPS virtuelles en attendant le correctif éditeur.
* Geler les déploiements introduisant de nouvelles dépendances vulnérables.
* Notifier les équipes produit et les fournisseurs concernés par la chaîne de dépendance.

#### Phase 4 — Activités post-incident

* Mettre à jour le SBOM et l'arbre de dépendances après remédiation.
* Revoir les SLA de correctifs à la lumière de l'incident et des scores EPSS observés.
* Intégrer le contrôle des dépendances transitives dans la CI/CD (blocage de build sur CVE critique).
* Documenter les leçons apprises et les délais réels de remédiation par équipe.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs l'exploitation effective des CVE identifiées comme présentes dans le parc.
* Vérifier l'absence de composants non référencés dans le SBOM (dépendances fantômes).
* Corréler les CVE tendance avec les actifs exposés pour prioriser la chasse.
* Contrôler l'intégrité des artefacts de build et des dépôts de paquets utilisés.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195** | Supply Chain Compromise : exploitation de bibliothèques tierces et de dépendances transitives non patchées. |
| **T1190** | Exploit Public-Facing Application : exploitation de vulnérabilités applicatives publiées (CVE) sur des composants exposés. |

---

### Sources

* [https://cvedatabase.com](https://cvedatabase.com)


---

<div id="quelquun-etait-en-train-de-sintroduire-dans-mes-serveurs-une-ia-les-a-interceptes-les-a-identifies-mirai-sure-a-91-les-a-bloques-et-a-ecrit-une-regle-pour-attraper-le-prochain-elle-na-pas-pu-deployer-cette-regle-avant-davoir-passe-5-000-evenements-reelsquatre-minutes-production-en-direct-rien-de-scenarisehttpsyoutubeo47iky7lw8winfosec-threatintel-blueteam-ai-detectionengineering"></div>

## Quelqu’un était en train de s’introduire dans mes serveurs. Une IA les a interceptés, les a identifiés (Mirai, sûre à 91 %), les a bloqués et a écrit une règle pour attraper le prochain. Elle n’a pas pu déployer cette règle avant d’avoir passé 5 000 événements réels.Quatre minutes. Production en direct. Rien de scénarisé.https://youtu.be/O47Iky7LW8w#infosec #threatintel #blueteam #AI #DetectionEngineering

### Résumé

Le message décrit un scénario d'intrusion sur des serveurs en production : une IA a détecté l'attaquant, l'a identifié comme Mirai avec un niveau de confiance de 91 %, l'a bloqué, puis a rédigé une règle de détection destinée à intercepter les tentatives suivantes. La règle n'a été déployée qu'après validation sur 5 000 événements réels. L'ensemble du processus se serait déroulé en quatre minutes, en production, sans mise en scène. Le contenu renvoie à une vidéo YouTube et porte les mots-clés infosec, threatintel, blueteam, AI et DetectionEngineering.

---

### Analyse opérationnelle

Ce cas illustre l'émergence de l'assistance par IA dans l'ingénierie de détection : classification de famille de malware, blocage automatisé et génération de règles. Pour un SOC, les points de vigilance sont la validation obligatoire des règles générées (ici contre 5 000 événements réels) afin de limiter les faux positifs, la traçabilité des décisions automatisées et la capacité à revenir en arrière en cas de blocage erroné. La détection de Mirai reste pertinente : les botnets IoT exploitent des identifiants par défaut et des services exposés, et génèrent des scans internes et des connexions sortantes vers des C2. Les équipes doivent disposer d'une télémétrie suffisante (processus, réseau, authentification) pour que l'automatisation soit fiable, et d'un garde-fou humain sur les actions de blocage en production.

---

### Implications stratégiques

L'automatisation de la détection et de la réponse réduit drastiquement le temps de réaction, ce qui modifie les attentes de performance des SOC et la planification des effectifs. Elle introduit toutefois un risque de dépendance à des modèles opaques et de dérive des règles générées, nécessitant une gouvernance de l'IA en cybersécurité (validation, audit, explicabilité). La persistance des botnets de type Mirai confirme que les objets connectés et serveurs mal durcis restent une source majeure de compromission à grande échelle, avec un risque de participation involontaire à des attaques DDoS.

---

### Recommandations

* Valider toute règle de détection générée automatiquement sur un corpus d'événements réels avant mise en production.
* Conserver une revue humaine et un mécanisme de rollback sur les actions de blocage automatisées.
* Durcir les serveurs et objets connectés exposés (identifiants par défaut, services inutiles, mises à jour).
* Surveiller les connexions sortantes vers des infrastructures de C2 de botnets IoT.
* Mesurer et documenter le délai de détection/réponse comme indicateur de performance du SOC.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Instrumenter les serveurs exposés avec une télémétrie suffisante (processus, connexions réseau, authentifications) pour l'analyse automatisée.
* Disposer d'un corpus d'événements réels (plusieurs milliers) pour valider toute nouvelle règle de détection avant mise en production.
* Définir un processus de validation des règles générées automatiquement (seuil de faux positifs, revue humaine).
* Préparer des procédures de blocage automatisé avec garde-fous pour éviter les blocages de production légitimes.

#### Phase 2 — Détection et analyse

* Détecter les comportements d'intrusion sur serveurs exposés (tentatives d'authentification, exécution de commandes, téléchargements).
* Utiliser la classification automatisée pour identifier la famille de malware (ici Mirai, avec un score de confiance de 91 %).
* Valider toute règle de détection générée contre un volume important d'événements réels avant déploiement.
* Alerter en temps quasi réel sur les indicateurs de botnet IoT (connexions sortantes vers C2, scans internes).

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement la source identifiée et les connexions vers l'infrastructure de commande et contrôle.
* Isoler les serveurs compromis du réseau de production.
* Déployer la règle de détection validée pour intercepter les tentatives suivantes.
* Réinitialiser les identifiants et révoquer les accès utilisés lors de l'intrusion.

#### Phase 4 — Activités post-incident

* Revoir la performance de la détection automatisée (taux de faux positifs, délai de détection).
* Intégrer la règle validée dans le référentiel de détection permanent.
* Analyser la chaîne d'intrusion complète pour identifier les contrôles défaillants.
* Documenter le temps de réponse de bout en bout (ici environ quatre minutes) comme référence de performance.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres serveurs présentant les mêmes signaux d'intrusion ou de botnet Mirai.
* Chasser les connexions sortantes anormales vers des infrastructures de C2 connues.
* Vérifier l'absence de persistance laissée par l'attaquant sur les hôtes touchés.
* Étendre la recherche aux équipements IoT et serveurs exposés du périmètre.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595** | Active Scanning : balayage des serveurs exposés à l'origine de la détection de l'intrusion. |
| **T1498** | Network Denial of Service : capacité de déni de service associée aux botnets de type Mirai. |
| **T1059** | Command and Scripting Interpreter : exécution de commandes sur les serveurs compromis. |

---

### Sources

* [https://youtu.be/O47Iky7LW8w](https://youtu.be/O47Iky7LW8w)


---

<div id="strangerdotnetthingsx509comjs-montrez-moi-chaque-objet-com-que-je-peux-appeler-avec-certutil"></div>

## StrangerDOTNETThings/x509com.js - montrez-moi chaque objet COM que je peux appeler avec certutil

### Résumé

Le dépôt GitHub secdev02/StrangerDOTNETThings contient un script JavaScript nommé x509com.js dont l'objet est d'énumérer les objets COM pouvant être invoqués via certutil. Le titre de la source constitue l'unique description disponible ; aucun texte additionnel n'est fourni.

---

### Analyse opérationnelle

certutil est un binaire signé Microsoft, présent nativement sur Windows, ce qui en fait un candidat classique de « living off the land » (LOLBAS) pour le téléchargement de fichiers, le décodage de charges ou le contournement de contrôles applicatifs. L'énumération des objets COM invocables via certutil élargit la surface d'exécution proxy : un attaquant peut chercher un objet COM non surveillé pour exécuter du code sans binaire tiers. Pour les équipes SOC, cela implique de journaliser systématiquement la ligne de commande de certutil, de détecter les invocations d'objets COM depuis des scripts et de surveiller les modifications de clés de registre COM. Les restrictions d'exécution (WDAC/AppLocker) et la limitation des scripts côté poste réduisent fortement ce vecteur.

---

### Implications stratégiques

L'abus de binaires légitimes signés rend la détection difficile et affaiblit les stratégies de blocage fondées sur les listes noires de fichiers. Les organisations doivent basculer vers une approche comportementale et une réduction de la surface d'exécution (application control, suppression des interpréteurs de script non nécessaires). La publication d'outils d'énumération COM renforce l'accessibilité de ces techniques à des attaquants peu sophistiqués.

---

### Recommandations

* Journaliser et alerter sur les exécutions de certutil avec arguments inhabituels.
* Restreindre l'exécution de certutil et des interpréteurs de script via WDAC/AppLocker.
* Surveiller les modifications de clés de registre COM (CLSID, InprocServer32).
* Détecter l'invocation d'objets COM depuis des scripts sur les postes utilisateurs.
* Maintenir une liste de référence des objets COM légitimement utilisés dans le parc.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les usages légitimes de certutil dans l'organisation et documenter les exceptions.
* Activer la journalisation des processus (Sysmon, EDR) avec capture de la ligne de commande complète.
* Activer l'audit des accès aux objets COM et des écritures dans le registre liées aux CLSID.
* Constituer une liste de référence des objets COM légitimement invoqués dans le parc.

#### Phase 2 — Détection et analyse

* Alerter sur l'exécution de certutil avec des arguments inhabituels (URL, décodage, -urlcache, -decode).
* Détecter l'invocation d'objets COM depuis des scripts (JavaScript, VBScript, PowerShell) sur des postes utilisateurs.
* Surveiller la création ou la modification de clés de registre COM (CLSID, InprocServer32) hors déploiement logiciel.
* Corréler l'exécution de certutil avec des connexions réseau sortantes ou des écritures de fichiers suspects.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre le processus suspect et isoler l'hôte concerné.
* Bloquer les connexions réseau initiées par le processus incriminé.
* Restreindre l'exécution de certutil aux seuls cas d'usage légitimes via AppLocker/WDAC.
* Révoquer les accès et identifiants susceptibles d'avoir été utilisés.

#### Phase 4 — Activités post-incident

* Analyser la chaîne d'exécution complète (script, objet COM, binaire proxy) pour identifier le vecteur initial.
* Mettre à jour les règles de détection à partir des artefacts observés.
* Revoir les restrictions d'exécution et la politique de scripts sur les postes.
* Documenter les objets COM légitimes pour affiner la liste de référence.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement les exécutions de certutil avec arguments suspects sur l'ensemble du parc.
* Identifier les hôtes ayant invoqué des objets COM inhabituels ou non référencés.
* Vérifier l'absence de persistance via détournement de composants COM.
* Comparer les artefacts observés aux techniques LOLBAS connues pour qualifier l'activité.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1218** | System Binary Proxy Execution : usage de certutil, binaire signé Microsoft, comme proxy d'exécution. |
| **T1559** | Inter-Process Communication : invocation d'objets COM depuis un script. |
| **T1059** | Command and Scripting Interpreter : script JavaScript x509com.js. |

---

### Sources

* [https://github.com/secdev02/StrangerDOTNETThings/blob/main/x509com.js](https://github.com/secdev02/StrangerDOTNETThings/blob/main/x509com.js)


---

<div id="kl-security-key-listed-in-pentest-tools-worth-a-closer-look-security-keys-are-often-treated-as-the-final-authentication-layer-so-understanding-their-attack-surface-matters-a-tool-that-probes-that-layer-is-the-kind-of-thing-worth-reading-carefully-before-deploying-anywhere-near-production-infosec-pentest-hardware-httpskitploitcomentoolsgithubkaraaslanlabskl-security-key"></div>

## kl-security-key listed in Pentest Tools — worth a closer look. Security keys are often treated as the final authentication layer, so understanding their attack surface matters. A tool that probes that layer is the kind of thing worth reading carefully before deploying anywhere near production. #infosec #pentest #hardware https://kitploit.com/en/tools/github/karaaslanlabs/kl-security-key

### Résumé

Le projet open source KL Security Key, développé par Karaaslan Labs, est un authentificateur FIDO2/WebAuthn expérimental basé sur une carte RP2040 en USB FIDO HID. Il dérive du projet polhenarejos/pico-fido et se présente comme un projet d'ingénierie/recherche, non certifié par la FIDO Alliance et non équivalent à un jeton commercial à haute assurance. Caractéristiques déclarées : versions CTAP FIDO_2_0, FIDO_2_1 et FIDO_2_3 ; présence utilisateur physique via bouton et support PIN/UV ; attestation Packed ES256 avec x5c et certificat propre à l'appareil ; AAGUID d9359dc7-6938-5822-b951-006507247d8f ; absence d'élément sécurisé ; distribution en source uniquement, sans binaire de firmware publié. Les tests rapportés incluent : enregistrement WebAuthn réussi, authentification/GetAssertion réussi, fournisseur Windows MicrosoftCtapHidProvider, chemin CTAP2 avec U2fProtocol=false, présence physique requise, chemin PIN/UV validé, signature d'attestation Packed réussie, vérification de la feuille d'attestation vers la KL Security Key Root CA réussie, concordance de l'AAGUID entre les données de l'authentificateur et l'extension du certificat, et enregistrement lié à l'appareil dans un tenant Microsoft Entra avec connexion physique réussie lorsque l'application de l'attestation est désactivée. Le projet précise explicitement ne pas revendiquer la certification FIDO Alliance, la protection de niveau élément sécurisé contre l'extraction physique, la confiance universelle des parties de confiance, l'équivalence avec YubiKey ou Nitrokey, la propriété des VID/PID USB, ni la certification Microsoft. Le fichier THREAT-MODEL.md est mis en avant comme lecture préalable obligatoire.

---

### Analyse opérationnelle

Les clés de sécurité matérielles sont souvent considérées comme le dernier rempart d'authentification ; ce projet montre qu'un authentificateur FIDO2 peut être construit sur du matériel à bas coût, sans élément sécurisé, et néanmoins interopérer avec Windows WebAuthn et Microsoft Entra. Pour les équipes sécurité, cela implique de ne pas se reposer uniquement sur la présence d'un facteur matériel : il faut contrôler l'AAGUID, appliquer l'attestation côté fournisseur d'identité et restreindre les modèles autorisés. L'absence d'élément sécurisé expose à l'extraction physique des secrets, ce qui est critique pour les comptes à privilèges. La validation de l'attestation Packed et la vérification de la chaîne jusqu'à la Root CA sont des points de contrôle exploitables pour détecter des clés non conformes. Enfin, la distribution en source uniquement et l'absence de binaire publié limitent le risque de chaîne d'approvisionnement, mais imposent une compilation et un provisionnement maîtrisés des matériels d'attestation.

---

### Implications stratégiques

La démocratisation des authentificateurs FIDO2 à bas coût brouille la frontière entre facteur d'authentification de confiance et matériel de recherche. Les organisations qui déploient FIDO2 comme rempart anti-phishing doivent formaliser une politique d'acceptation des authentificateurs (certification, élément sécurisé, attestation) sous peine de voir leur niveau d'assurance réel s'effondrer. Ce type de projet accélère aussi l'innovation et la recherche sur la surface d'attaque des clés de sécurité, ce qui est utile défensivement mais fournit également des outils d'exploration aux attaquants. Décisionnellement, cela renforce la nécessité d'une gouvernance de l'identité couvrant le cycle de vie complet des facteurs matériels.

---

### Recommandations

* Définir une liste d'authentificateurs FIDO2 autorisés et exiger la certification FIDO Alliance pour les comptes sensibles.
* Activer et appliquer l'attestation côté fournisseur d'identité lorsque le niveau d'assurance l'exige.
* Contrôler les AAGUID enregistrés et alerter sur tout identifiant non référencé.
* Restreindre l'enregistrement de nouvelles clés de sécurité aux administrateurs habilités.
* Privilégier des jetons disposant d'un élément sécurisé pour les accès à privilèges.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir une politique d'acceptation des authentificateurs FIDO2 (modèles autorisés, exigence de certification FIDO Alliance).
* Activer l'application de l'attestation côté fournisseur d'identité lorsque le niveau d'assurance l'exige.
* Inventorier les clés de sécurité enregistrées et leur AAGUID.
* Documenter les procédures de révocation et de réenregistrement des facteurs matériels.

#### Phase 2 — Détection et analyse

* Alerter sur l'enregistrement d'authentificateurs dont l'AAGUID n'est pas dans la liste autorisée.
* Détecter les enregistrements de clés de sécurité hors processus d'onboarding ou hors périmètre géographique attendu.
* Surveiller les tentatives d'authentification échouées répétées sur des comptes à privilèges utilisant FIDO2.
* Contrôler la cohérence entre données d'attestation et certificat présenté.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement tout authentificateur non autorisé ou non certifié enregistré sur un compte sensible.
* Suspendre les comptes concernés en cas de doute sur l'intégrité du facteur.
* Restreindre l'enregistrement de nouvelles clés aux administrateurs habilités.
* Renforcer temporairement les contrôles d'accès sur les comptes à privilèges.

#### Phase 4 — Activités post-incident

* Revoir la politique d'attestation et la liste des modèles d'authentificateurs autorisés.
* Auditer l'ensemble des enregistrements FIDO2 pour détecter d'autres clés non conformes.
* Documenter les écarts entre la politique d'authentification et la configuration réelle du fournisseur d'identité.
* Sensibiliser les utilisateurs aux risques liés aux clés non certifiées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les enregistrements d'authentificateurs présentant des AAGUID inconnus ou non référencés.
* Analyser les journaux d'authentification pour détecter des schémas d'usage anormaux de clés matérielles.
* Vérifier l'absence de clés enregistrées depuis des postes ou réseaux non autorisés.
* Contrôler l'intégrité des certificats d'attestation utilisés dans l'organisation.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1200** | Hardware Additions : introduction d'un authentificateur matériel non certifié dans la chaîne d'authentification. |
| **T1556** | Modify Authentication Process : manipulation d'un facteur d'authentification matériel (clé de sécurité FIDO2). |

---

### Sources

* [https://kitploit.com/en/tools/github/karaaslanlabs/kl-security-key](https://kitploit.com/en/tools/github/karaaslanlabs/kl-security-key)


---

<div id="bold-spring-nursery-par-play"></div>

## Bold Spring Nursery par play

### Résumé

La source correspond à la page RansomLook dédiée au groupe rançongiciel Play. Le titre référence une victime (« Bold Spring Nursery ») et la page affiche un compteur « 0/32 » ainsi qu'un statut hors ligne. Aucun détail technique supplémentaire n'est fourni dans le contenu.

---

### Analyse opérationnelle

Le groupe Play opère selon un modèle de double extorsion : exfiltration de données puis chiffrement, avec publication des victimes sur un site de fuite. Pour les équipes SOC, la surveillance des sources de type RansomLook permet de détecter précocement l'apparition de son organisation parmi les victimes revendiquées, souvent avant la communication officielle. Les indicateurs à surveiller en amont incluent les accès distants anormaux (VPN, RDP), les exfiltrations volumétriques et les tentatives de désactivation des outils de sécurité. La préparation repose sur des sauvegardes hors ligne testées, une segmentation réseau stricte et la limitation des accès administratifs.

---

### Implications stratégiques

L'activité continue des groupes de rançongiciel comme Play maintient une pression élevée sur les organisations de toutes tailles et de tous secteurs, avec un risque de perte de données, d'interruption d'activité et d'atteinte réputationnelle. La publication des victimes sur des sites de fuite crée un risque médiatique et juridique immédiat, indépendamment du paiement. Décisionnellement, cela impose de traiter la résilience (sauvegardes, plan de continuité) et la gestion de crise comme des investissements prioritaires, et de préparer une communication de crise avant tout incident.

---

### Recommandations

* Surveiller les sites de fuite et les agrégateurs (RansomLook) pour détecter les revendications visant l'organisation.
* Tester régulièrement la restauration des sauvegardes hors ligne.
* Restreindre et superviser les accès distants (VPN, RDP) avec MFA.
* Segmenter le réseau pour limiter les mouvements latéraux.
* Préparer un plan de communication de crise et les obligations de notification réglementaire.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier la couverture des sauvegardes hors ligne et tester régulièrement les restaurations.
* Segmenter le réseau et restreindre les accès administratifs (moindre privilège, MFA).
* Surveiller les sources de type RansomLook pour détecter l'apparition de son organisation parmi les victimes.
* Préparer une cellule de crise incluant communication, juridique et direction générale.

#### Phase 2 — Détection et analyse

* Détecter les signes de chiffrement massif de fichiers et les notes de rançon.
* Alerter sur les exfiltrations volumétriques sortantes et les accès inhabituels aux partages réseau.
* Surveiller les identifiants compromis et les connexions VPN/RDP anormales.
* Détecter la désactivation d'outils de sécurité ou la suppression de journaux.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments et hôtes affectés du réseau.
* Désactiver les comptes compromis et révoquer les sessions actives.
* Couper les accès distants (VPN, RDP) pendant la phase de crise.
* Préserver les preuves (images mémoire, journaux) avant toute remédiation.

#### Phase 4 — Activités post-incident

* Restaurer les systèmes depuis des sauvegardes saines et vérifiées.
* Notifier les autorités et les parties prenantes conformément aux obligations réglementaires.
* Analyser le vecteur initial et les mouvements latéraux pour corriger les failles.
* Revoir la stratégie de sauvegarde, de segmentation et de gestion des accès.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts du groupe Play (binaires, clés de registre, comptes créés) sur l'ensemble du parc.
* Identifier les accès aux partages et les exfiltrations antérieures au chiffrement.
* Vérifier l'absence de persistance résiduelle sur les hôtes restaurés.
* Corréler les indicateurs avec les publications de la page RansomLook du groupe.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact : chiffrement des données par le rançongiciel Play. |
| **T1657** | Financial Theft : extorsion par demande de rançon et menace de publication des données. |
| **T1567** | Exfiltration Over Web Service : exfiltration de données avant chiffrement en vue de la double extorsion. |

---

### Sources

* [https://www.ransomlook.io//group/play](https://www.ransomlook.io//group/play)


---

<div id="nouvel-article-de-blog-dun-groupe-de-rancongiciel-nom-du-groupe-kazu-titre-de-larticle-tgd-digital-government-platform-ar-organisation-tgd-digital-government-platform-localisation-ar-secteur-gouvernement-infos-httpsctifyigroupskazuhtmlransomware-cti-threatintelligence-cybersecurity-infosec"></div>

## 🚨Nouvel article de blog d’un groupe de rançongiciel !🚨Nom du groupe : kazu Titre de l’article : TGD: Digital Government Platform - AR Organisation : TGD: Digital Government Platform Localisation : 🇦🇷 AR Secteur : Gouvernement Infos : https://cti.fyi/groups/kazu.html#ransomware #cti #threatintelligence #cybersecurity #infosec

### Résumé

Le groupe de rançongiciel « kazu » a publié une nouvelle victime sur son site de fuite : la plateforme gouvernementale numérique TGD, située en Argentine (AR), dans le secteur gouvernemental. L'annonce provient du flux de suivi cti.fyi, qui recense les publications des groupes de rançongiciel. Aucun détail n'est fourni sur le volume de données exfiltrées, le vecteur d'intrusion initial ou les éventuelles demandes de rançon.

---

### Analyse opérationnelle

La compromission d'une plateforme gouvernementale numérique expose des services critiques et potentiellement des données citoyennes. Pour un SOC, l'annonce sur un site de fuite constitue un signal de confirmation tardif : l'intrusion est généralement antérieure de plusieurs jours ou semaines. Les équipes doivent prioriser la recherche d'exfiltration, de persistance et de mouvements latéraux, et vérifier l'intégrité des sauvegardes avant toute restauration. La surface d'attaque typique inclut les accès RDP/VPN exposés, les comptes de service à privilèges élevés et les logiciels non patchés.

---

### Implications stratégiques

L'attaque d'une entité gouvernementale argentine s'inscrit dans une tendance de ciblage des infrastructures publiques, à fort impact réputationnel et de continuité de service. Elle souligne la nécessité pour les administrations de traiter la cyberdéfense comme un enjeu de souveraineté et de confiance citoyenne. Les conséquences décisionnelles incluent le renforcement des budgets de sécurité, la mutualisation des capacités de réponse au niveau national et l'obligation de notification aux autorités de régulation.

---

### Recommandations

* Vérifier immédiatement si l'organisation figure ou est liée à la victime listée et activer la cellule de crise.
* Auditer les accès distants exposés (RDP, VPN, portails) et imposer le MFA partout.
* Contrôler l'intégrité et l'isolation des sauvegardes ; tester une restauration réelle.
* Surveiller les sites de fuite et les canaux de négociation pour détecter toute publication de données.
* Renforcer la segmentation réseau entre services administratifs et systèmes exposés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les actifs exposés du secteur public argentin et cartographier les dépendances aux plateformes gouvernementales numériques.
* Vérifier la couverture EDR/SIEM sur les serveurs critiques et les sauvegardes hors ligne immuables.
* Préparer une cellule de crise incluant communication institutionnelle et conseil juridique (notification autorité de protection des données).
* Tester les procédures de restauration et les scénarios de rançon sur environnements isolés.

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux partages de fichiers et les volumes massifs de lecture/écriture (indicateur de staging avant exfiltration).
* Détecter l'exécution d'outils de chiffrement, la suppression des clichés instantanés (vssadmin, wbadmin) et la désactivation des journaux.
* Corréler les alertes avec les publications du site de fuite kazu pour confirmer l'appartenance de la victime.
* Analyser les connexions sortantes vers des services de transfert de fichiers et de stockage cloud non autorisés.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments réseau touchés et révoquer les comptes compromis (sessions, jetons, clés API).
* Couper les accès VPN/RDP exposés et forcer la rotation des secrets d'administration.
* Bloquer les IOC identifiés au niveau proxy, DNS et pare-feu périmétrique.
* Préserver les preuves forensiques (mémoire, disques, journaux) avant toute remédiation.

#### Phase 4 — Activités post-incident

* Réaliser un retour d'expérience formel et mettre à jour le plan de réponse à incident.
* Renforcer l'authentification multifacteur, la segmentation et le principe du moindre privilège.
* Évaluer l'exposition des données personnelles et déclencher les notifications réglementaires requises.
* Revoir la stratégie de sauvegarde (règle 3-2-1, copies immuables, tests réguliers).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts de persistance (tâches planifiées, services, comptes créés) sur l'ensemble du parc.
* Chasser les mouvements latéraux via SMB/WMI/PsExec et les connexions administratives inhabituelles.
* Analyser les journaux historiques pour identifier la fenêtre d'intrusion initiale et le vecteur d'accès.
* Surveiller les réutilisations d'infrastructure et les futures publications du groupe kazu.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1657** | Financial Theft (extorsion par rançon) |
| **T1591** | Gather Victim Org Information |

---

### Sources

* [https://cti.fyi/groups/kazu.html](https://cti.fyi/groups/kazu.html)


---

<div id="la-securite-multi-locataire-exige-une-isolation-absolue-jusqua-la-couche-de-stockage-cloudflare-a-recemment-partage-des-details-sur-la-maniere-dont-elle-a-traite-une-vulnerabilite-dexposition-de-donnees-entre-locataires-affectant-cloudflare-containers-et-cloudflare-sandboxes"></div>

## La sécurité multi-locataire exige une isolation absolue jusqu’à la couche de stockage. Cloudflare a récemment partagé des détails sur la manière dont elle a traité une vulnérabilité d’exposition de données entre locataires affectant Cloudflare Containers et Cloudflare Sandboxes.

### Résumé

Le 4 septembre 2026, le chercheur Oren Yomtov (Accomplish) a signalé via le programme de bug bounty de Cloudflare une vulnérabilité affectant Cloudflare Containers et Sandboxes. Les pools de stockage en thin provisioning utilisaient l'option skip_block_zeroing : lorsqu'un bloc physique de 64 KiB était restitué au pool partagé puis réattribué à un nouveau conteneur, une écriture partielle (4 KiB) laissait jusqu'à 60 KiB de données résiduelles lisibles via une lecture brute du périphérique. Un client avec un compte Workers Paid pouvait ainsi lire des données résiduelles d'autres conteneurs hébergés sur le même hôte physique, sans pouvoir cibler un client ou un hôte précis. Cloudflare a corrigé le problème sur l'ensemble de la flotte (suppression de skip_block_zeroing, drainage des nœuds hors heures de pointe, redémarrage des VM, purge des snapshots). Aucune preuve d'exploitation malveillante n'a été identifiée dans la télémétrie historique, et aucune action client n'est requise.

---

### Analyse opérationnelle

Cette vulnérabilité illustre un risque d'exposition inter-locataires au niveau de la couche stockage, difficile à détecter car elle ne génère pas d'alerte applicative classique. Pour un SOC, la détection repose sur la surveillance des accès bruts aux périphériques de bloc et des motifs d'écriture inhabituels (petites écritures alignées sur 64 KiB). La réponse consiste à appliquer les correctifs fournisseur, à purger les blocs recyclés et à chiffrer les données sensibles au niveau applicatif afin de rendre inexploitable toute donnée résiduelle. La surface d'attaque est limitée aux environnements multi-tenant mutualisant le stockage physique.

---

### Implications stratégiques

L'incident rappelle que la sécurité multi-tenant ne peut se limiter à l'isolation logique : elle doit descendre jusqu'à la couche stockage. Pour les organisations dépendantes du cloud, cela renforce l'exigence de garanties contractuelles d'isolation, de transparence des fournisseurs et de chiffrement de bout en bout. La tendance est à une pression accrue sur les fournisseurs cloud pour documenter leurs pratiques de gestion du stockage et pour une meilleure traçabilité des incidents inter-locataires.

---

### Recommandations

* Vérifier auprès du fournisseur l'application effective du correctif sur les environnements utilisés.
* Chiffrer les données sensibles au repos au niveau applicatif, indépendamment du chiffrement fournisseur.
* Surveiller les accès raw aux périphériques de stockage depuis les conteneurs.
* Intégrer des clauses d'isolation et de notification d'incident dans les contrats cloud.
* Réaliser un audit des données résiduelles sur les volumes et snapshots recyclés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les charges de travail hébergées sur des plateformes multi-tenant et identifier les données sensibles traitées.
* Vérifier les engagements contractuels et les garanties d'isolation fournies par les fournisseurs cloud.
* Mettre en place une veille sur les avis de sécurité des fournisseurs et un canal de notification rapide.
* Documenter les procédures de rotation de secrets et de chiffrement au repos applicatif.

#### Phase 2 — Détection et analyse

* Surveiller les accès bruts aux périphériques de stockage (/dev/vdc, lectures raw) depuis des conteneurs.
* Détecter les écritures anormalement petites et alignées sur des blocs de 64 KiB, signature du PoC d'exploitation.
* Analyser les journaux d'I/O disque pour repérer des lectures de blocs non écrits par le conteneur courant.
* Corréler avec les alertes du fournisseur et les rapports de bug bounty.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer les correctifs ou mesures d'atténuation publiés par le fournisseur (désactivation de skip_block_zeroing).
* Migrer ou redéployer les charges de travail sensibles sur des nœuds assainis après purge des blocs.
* Chiffrer les données sensibles au niveau applicatif pour réduire l'impact d'une fuite résiduelle.
* Isoler les conteneurs suspects et préserver les images et snapshots pour analyse.

#### Phase 4 — Activités post-incident

* Exiger du fournisseur un rapport d'investigation et une attestation d'absence d'exploitation malveillante.
* Réévaluer les exigences d'isolation dans les appels d'offres et contrats cloud.
* Mettre à jour la politique de classification et de chiffrement des données hébergées.
* Communiquer de manière transparente aux parties prenantes et autorités si des données personnelles sont concernées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des lectures raw de disques et des accès à /dev/vdc dans les journaux de conteneurs.
* Analyser les images de conteneurs pour détecter des outils de lecture de blocs ou de carving de données.
* Vérifier l'absence de données résiduelles exploitables dans les snapshots et volumes recyclés.
* Surveiller les publications de recherche et les PoC publics liés à cette vulnérabilité.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1213** | Data from Information Repositories |
| **T1530** | Data from Cloud Storage |
| **T1552** | Unsecured Credentials |

---

### Sources

* [https://blog.cloudflare.com/containers-cross-tenant-vulnerability/](https://blog.cloudflare.com/containers-cross-tenant-vulnerability/)


---

<div id="apex-flash-un-modele-a-poids-ouverts-pour-la-recherche-en-securite-post-entraine-sur-des-vulnerabilites-reelles-issues-de-notre-jeu-de-donnees-proprietaire"></div>

## Apex Flash - un modèle à poids ouverts pour la recherche en sécurité, post-entraîné sur des vulnérabilités réelles issues de notre jeu de données propriétaire.

### Résumé

Cantina Security, en partenariat avec Yeta Labs, annonce la sortie d'apex-flash-1, un modèle open-weights destiné à la recherche en sécurité, post-entraîné sur des vulnérabilités réelles issues d'un jeu de données propriétaire. L'annonce s'inscrit dans un débat sur l'accès aux capacités cyber des systèmes d'IA : les auteurs soutiennent que la restriction des modèles propriétaires crée une asymétrie, les attaquants pouvant exécuter localement des modèles ouverts et retirer les garde-fous, tandis que les défenseurs restent contraints. Le texte établit un parallèle avec le débat des années 1990-2000 sur les outils offensifs (Nmap, Metasploit) devenus infrastructure standard de la sécurité moderne.

---

### Analyse opérationnelle

La disponibilité de modèles open-weights spécialisés en sécurité abaisse la barrière technique pour la recherche de vulnérabilités, mais aussi pour la génération d'exploits. Pour les équipes SOC/IT, cela implique une augmentation probable du volume et de la vitesse des tentatives d'exploitation automatisées, et la nécessité de contrôler l'exécution de modèles non approuvés sur le parc. La détection repose sur la surveillance des dépôts de modèles, des exécutions locales et des flux vers des API non autorisées. Les mesures techniques incluent le blocage des modèles non approuvés, l'isolation des environnements de test et le DLP sur les données sensibles.

---

### Implications stratégiques

L'essor des modèles ouverts spécialisés en cybersécurité modifie l'équilibre des capacités entre attaquants et défenseurs et remet en cause les stratégies de contrôle par les politiques d'usage des modèles propriétaires. Les organisations doivent anticiper une accélération de la découverte et de l'exploitation de vulnérabilités, et adapter leur gouvernance de l'IA. Sur le plan géopolitique, la question de la diffusion des capacités cyber assistées par IA devient un enjeu de régulation et de souveraineté technologique.

---

### Recommandations

* Établir une politique claire d'usage des modèles d'IA en sécurité, avec liste blanche des modèles approuvés.
* Surveiller l'exécution locale de modèles open-weights non filtrés sur le parc.
* Renforcer la gestion des vulnérabilités face à l'accélération de la découverte automatisée.
* Protéger les jeux de données propriétaires de vulnérabilités par des contrôles d'accès stricts.
* Suivre les évolutions réglementaires sur l'IA dual-use et les capacités cyber.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir une politique d'usage des modèles d'IA en interne, distinguant usages défensifs et offensifs.
* Évaluer les risques liés à l'exécution locale de modèles open-weights non filtrés.
* Former les équipes sécurité à l'utilisation encadrée de l'IA pour la recherche de vulnérabilités.
* Mettre en place une gouvernance des données propriétaires utilisées pour l'entraînement ou l'évaluation.

#### Phase 2 — Détection et analyse

* Surveiller l'exécution de modèles d'IA non approuvés sur les postes et serveurs de l'organisation.
* Détecter les tentatives d'utilisation de modèles pour générer des exploits ou du code offensif.
* Analyser les flux sortants vers des dépôts de modèles et des API non autorisées.
* Corréler les alertes avec les campagnes de recherche de vulnérabilités automatisées.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'exécution de modèles non approuvés et restreindre les accès aux dépôts de modèles.
* Isoler les environnements de test utilisés pour l'évaluation de modèles offensifs.
* Révoquer les accès aux jeux de données sensibles utilisés pour l'entraînement.
* Appliquer des contrôles de sortie (DLP) sur les données manipulées par les modèles.

#### Phase 4 — Activités post-incident

* Mettre à jour la politique d'usage de l'IA et les procédures d'approbation des modèles.
* Documenter les enseignements sur les risques dual-use et les diffuser aux parties prenantes.
* Réévaluer les contrôles d'accès aux données propriétaires de vulnérabilités.
* Aligner la stratégie IA sur les cadres réglementaires émergents.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'utilisation de modèles open-weights pour la génération d'exploits.
* Analyser les journaux d'accès aux datasets de vulnérabilités et aux dépôts internes.
* Surveiller les publications de modèles spécialisés sécurité et leurs capacités offensives.
* Évaluer l'exposition de l'organisation à des campagnes automatisées de découverte de vulnérabilités.

---

### Sources

* [https://www.cantina.security/apex-flash](https://www.cantina.security/apex-flash)


---

<div id="lockbit-publie-des-donnees-sur-danciens-employes-de-forus-a-la-suite-de-lincident-signale-au-cmf"></div>

## LockBit publie des données sur d’anciens employés de Forus à la suite de l’incident signalé au CMF

### Résumé

Le 18 septembre 2026, l'entreprise chilienne de commerce de détail et de gros Forus S.A. a été listée sur le site de fuite du groupe de rançongiciel LockBit, sans publication immédiate de données. Les données ont ensuite été exposées : une archive compressée de 98 GiB (environ 105 GB) contenant notamment un fichier « Distribuidores » (téléphones, courriels, noms) et un fichier « Finiquitos » listant 2 737 travailleurs finiquités en 2022, avec des champs tels que noms, RUT, date de naissance, nationalité, sexe, état civil, profession, poste, région, commune, adresse, téléphone, courriel, chef et RUT du chef. Le 16 septembre, Forus avait publié un communiqué indiquant avoir détecté le 15 septembre une atteinte à certains systèmes par un agent externe, avoir activé ses protocoles de prévention, détection et réponse avec l'appui d'experts, et affirmé que l'incident était contenu et n'impliquait pas de données personnelles de clients ou de collaborateurs. Ce communiqué est antérieur au listage et à la publication des fichiers. L'auteur de l'article a contacté Forus pour signaler l'exposition des données personnelles d'anciens travailleurs, en contradiction avec le communiqué transmis à la CMF.

---

### Analyse opérationnelle

La fuite expose des données d'identité très complètes (RUT, adresse, coordonnées, hiérarchie) exploitables pour du phishing ciblé, de la fraude à l'identité et de l'ingénierie sociale visant les anciens employés et leurs managers. Pour un SOC, la priorité est la détection d'activités post-fuite : campagnes de phishing ciblant les personnes listées, usurpation d'identité et tentatives d'accès aux comptes. La réponse inclut la notification des personnes affectées, la surveillance renforcée des comptes et la vérification de l'intégrité des sauvegardes. La contradiction entre le communiqué initial et la publication des données souligne l'importance d'une évaluation forensique complète avant toute communication publique.

---

### Implications stratégiques

Cet incident illustre la persistance de LockBit et la menace que représente la double extorsion pour le secteur du retail en Amérique latine. Il met en évidence un risque réputationnel et juridique majeur lorsqu'une organisation minimise publiquement l'impact d'un incident avant la fin de l'investigation. Les conséquences décisionnelles incluent le renforcement de la gouvernance des données RH, l'amélioration de la communication de crise et l'anticipation des obligations de notification réglementaire.

---

### Recommandations

* Notifier les anciens employés affectés et les sensibiliser au phishing ciblé et à la fraude à l'identité.
* Réaliser une investigation forensique complète avant toute communication publique sur l'étendue de l'incident.
* Restreindre l'accès aux fichiers RH sensibles et chiffrer les données personnelles au repos.
* Renforcer la surveillance des comptes et des accès distants avec MFA.
* Coordonner avec la CMF et les autorités de protection des données pour les obligations de notification.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les données RH et clients sensibles et leur localisation (fichiers XLSX, bases RH, partages).
* Vérifier la couverture EDR/SIEM et l'isolation des sauvegardes hors ligne.
* Préparer les procédures de notification aux autorités (CMF, protection des données) et aux personnes affectées.
* Former les équipes RH et support à reconnaître le phishing ciblé post-fuite.

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux partages RH et les volumes massifs de lecture de fichiers.
* Détecter l'exécution d'outils de chiffrement et la suppression des clichés instantanés.
* Corréler les alertes avec les publications du site de fuite LockBit.
* Analyser les connexions sortantes vers des services de transfert de fichiers non autorisés.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis et révoquer les comptes à privilèges.
* Bloquer les accès distants exposés et forcer la rotation des secrets.
* Préserver les preuves forensiques avant remédiation.
* Suspendre temporairement les partages de fichiers contenant des données personnelles.

#### Phase 4 — Activités post-incident

* Notifier les personnes affectées et les autorités conformément à la réglementation chilienne.
* Renforcer le MFA, la segmentation et le principe du moindre privilège.
* Revoir la stratégie de sauvegarde et tester les restaurations.
* Mettre en place une surveillance renforcée du phishing ciblé sur les anciens employés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts de persistance et les mouvements latéraux sur le parc.
* Analyser les journaux historiques pour identifier la fenêtre d'intrusion initiale.
* Rechercher la présence de fichiers exfiltrés (Distribuidores, Finiquitos) sur des canaux externes.
* Surveiller les réutilisations d'infrastructure et les futures publications de LockBit.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1657** | Financial Theft (extorsion par rançon) |
| **T1567** | Exfiltration Over Web Service |
| **T1589** | Gather Victim Identity Information |

---

### Sources

* [https://www.security-chu.com/2026/10/lockbit-publica-datos-incidente-de-ciberseguridad-Forus.html](https://www.security-chu.com/2026/10/lockbit-publica-datos-incidente-de-ciberseguridad-Forus.html)
* [https://newschu.substack.com/p/lockbit-publica-datos-de-ex-trabajadores](https://newschu.substack.com/p/lockbit-publica-datos-de-ex-trabajadores)
