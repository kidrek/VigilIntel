# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [ASCII smuggling : de l'injection de prompt IA à l'évasion anti-phishing](#ascii-smuggling-de-linjection-de-prompt-ia-a-levasion-anti-phishing)
  * [Tendances malware et vulnérabilités du S1 2026 : l'abus d'outils légitimes au cœur des intrusions](#tendances-malware-et-vulnerabilites-du-s1-2026-labus-doutils-legitimes-au-cur-des-intrusions)
  * [Un opérateur sinophone utilise des agents IA (framework SecFlow) contre des systèmes gouvernementaux et éducatifs en Asie](#un-operateur-sinophone-utilise-des-agents-ia-framework-secflow-contre-des-systemes-gouvernementaux-et-educatifs-en-asie)
  * [GHOSTWORKER : implant furtif sur passerelles UniFi rappelant via les DNS de Google](#ghostworker-implant-furtif-sur-passerelles-unifi-rappelant-via-les-dns-de-google)
  * [Node.js : le retour d'une vieille technique d'exécution et de persistance détournée](#nodejs-le-retour-dune-vieille-technique-dexecution-et-de-persistance-detournee)
  * [SigmaHQ : mises à jour du dépôt Sigma — renommage des règles appxdeployment-server et ajout de tests de régression](#sigmahq-mises-a-jour-du-depot-sigma-renommage-des-regles-appxdeployment-server-et-ajout-de-tests-de-regression)
  * [Space Bears : deux nouvelles victimes revendiquées sur son site de fuite (SGLA et Studio Oculistico Ciraci)](#space-bears-deux-nouvelles-victimes-revendiquees-sur-son-site-de-fuite-sgla-et-studio-oculistico-ciraci)
  * [Outils de pentest autonomes : un classement critérié relance le débat sur la supervision humaine des exploits automatiques](#outils-de-pentest-autonomes-un-classement-criterie-relance-le-debat-sur-la-supervision-humaine-des-exploits-automatiques)
  * [Italie : de fausses notifications de remboursement TARI servent d'appât à de nouvelles campagnes de phishing contre PagoPA](#italie-de-fausses-notifications-de-remboursement-tari-servent-dappat-a-de-nouvelles-campagnes-de-phishing-contre-pagopa)
  * [Compromission de l'infrastructure du registre de Coder pour pousser des modules malveillants](#compromission-de-linfrastructure-du-registre-de-coder-pour-pousser-des-modules-malveillants)
  * [Plex presse ses utilisateurs de corriger des vulnérabilités de Plex Media Server, encore sans identifiants CVE](#plex-presse-ses-utilisateurs-de-corriger-des-vulnerabilites-de-plex-media-server-encore-sans-identifiants-cve)
  * [Ephemora Cell : un runtime WASM à capacités pour exécuter en sandbox le code généré par les agents IA](#ephemora-cell-un-runtime-wasm-a-capacites-pour-executer-en-sandbox-le-code-genere-par-les-agents-ia)
  * [Deux « Nephrology Associates » victimes de cyberattaques : une seule a divulgué l'incident](#deux-nephrology-associates-victimes-de-cyberattaques-une-seule-a-divulgue-lincident)
  * [Ransomware « agentique » : une entreprise neutralisée en dix heures, l'IA laisse un audit de 80 pages](#ransomware-agentique-une-entreprise-neutralisee-en-dix-heures-lia-laisse-un-audit-de-80-pages)
  * [Un ressortissant russe inculpé pour exploitation d'une plateforme de freelance en ligne et distribution de malware à des milliers de victimes](#un-ressortissant-russe-inculpe-pour-exploitation-dune-plateforme-de-freelance-en-ligne-et-distribution-de-malware-a-des-milliers-de-victimes)
  * [Clé maîtresse développeur exposée et notification d'incident tardive : rotation d'urgence et audit du stockage des identifiants](#cle-maitresse-developpeur-exposee-et-notification-dincident-tardive-rotation-durgence-et-audit-du-stockage-des-identifiants)
  * [CERT-EU Cyber Brief 26-09 : panorama des menaces d'août 2026](#cert-eu-cyber-brief-26-09-panorama-des-menaces-daout-2026)
  * [Le Monde : une cyberattaque qualifiée de sans précédent ébranle le notariat français](#le-monde-une-cyberattaque-qualifiee-de-sans-precedent-ebranle-le-notariat-francais)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage de la menace du jour est dominé par le volet technique : 56 vulnérabilités recensées, dont probablement plusieurs activement exploitées, imposent une priorisation immédiate des correctifs sur les actifs exposés. Les 18 incidents de fuite de données signalés confirment une pression soutenue sur les données personnelles et corporatives, suggérant un cycle d'exploitation rapide des failles récemment divulguées. L'absence totale de publication sur des acteurs de la menace (0) est notable et reflète vraisemblablement un creux de reporting plutôt qu'une accalmie réelle des activités offensives. Le volet géopolitique reste marginal (1), sans signal de tension majeure susceptible d'impacter le cyberpaysage à court terme. Les 3 publications réglementaires méritent une revue conformité, notamment si elles concernent NIS2, DORA ou les obligations de notification d'incidents. La corrélation entre le volume de vulnérabilités et celui des fuites indique un raccourcissement des délais entre divulgation et compromission. Recommandation : renforcer la gestion des correctifs, vérifier l'exposition des systèmes face aux CVE critiques des dernières 48 heures et maintenir une vigilance accrue sur les canaux de fuite de données.

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
| **France, États-Unis, Europe** | Technologie / Défense / Administration publique | Souveraineté numérique et tensions transatlantiques autour des données et de la surveillance | Le patron de Palantir, Alex Karp, a déclaré que la France se « fera du mal » en tournant le dos aux géants technologiques américains, dans un contexte de débat accru sur la souveraineté numérique française et européenne. Cette déclaration intervient alors que Paris privilégie de plus en plus des solutions souveraines pour le traitement de données sensibles et les besoins de renseignement (DGSI). Elle illustre la pression exercée par les fournisseurs américains face à la stratégie européenne d'autonomie technologique, et met en évidence la tension entre performance des solutions US (analyse de données massives, capacités de surveillance) et exigences de maîtrise nationale des données, notamment au regard des législations extraterritoriales américaines (CLOUD Act, FISA). Ce bras de fer rhétorique s'inscrit dans une dynamique plus large de reconfiguration des dépendances technologiques transatlantiques, avec des enjeux directs pour les marchés publics français et les capacités de renseignement. | [https://www.france24.com/fr/am%C3%A9riques/20260903-patron-palantir-france-se-fera-du-mal-tournant-le-dos-g%C3%A9ant-am%C3%A9ricain-donn%C3%A9es-surveillance-dgsi-souverainet%C3%A9](https://www.france24.com/fr/am%C3%A9riques/20260903-patron-palantir-france-se-fera-du-mal-tournant-le-dos-g%C3%A9ant-am%C3%A9ricain-donn%C3%A9es-surveillance-dgsi-souverainet%C3%A9) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Désignation de l'organisation italienne Autistici/Inventati comme « Specially Designated Global Terrorist » par le gouvernement américain (26 août 2026) et déclaration de solidarité d'EDRi | Gouvernement des États-Unis (mesure de désignation « Specially Designated Global Terrorist ») | 2026-09-03 | États-Unis, avec effets extrateritoriaux touchant l'Union européenne et les prestataires financiers mondiaux | Désignation de l'organisation italienne Autistici/Inventati comme « Specially Designated Global Terrorist » par le gouvernement américain (26 août 2026) et déclaration de solidarité d'EDRi | Le 26 août 2026, le gouvernement américain a désigné le collectif italien Autistici/Inventati (A/I), hébergeur associatif à but non lucratif actif depuis 2001, comme « Specially Designated Global Terrorist », l'accusant de fournir une infrastructure numérique à des « militants d'extrême gauche violents ». Les effets ont été immédiats : le registre américain Public Interest Registry a désactivé le domaine autistici[.]org (rendant le site inaccessible), PayPal a saisi leur compte et la Banca Etica pourrait clôturer leur compte par crainte de sanctions secondaires. L'obligation imposée aux entreprises américaines de rompre tout lien économique avec A/I risque d'isoler l'organisation vis-à-vis des banques et institutions financières non américaines. A/I héberge environ 16 000 boîtes mail, 1 500 sites web, 5 500 listes de diffusion et 10 000 blogs utilisés par des collectifs, syndicats, journalistes et chercheurs. EDRi estime que cette mesure, prise sans procédure régulière, porte atteinte aux articles 7, 11 et 12 de la Charte des droits fondamentaux de l'UE (vie privée, liberté d'expression, liberté d'association) et constitue une escalade contre les communications sécurisées, les alternatives aux plateformes des Big Tech et l'organisation démocratique de la société civile, avec un effet dissuasif (chilling effect) sur l'ensemble de l'écosystème. | `hxxps://edri[.]org/our-work/edri-solidarity-statement-autistici-inventati/` |
| Mise à jour de la FAQ 1331 du PCI Security Standards Council relative à l'utilisation des critères d'éligibilité SAQ dans les évaluations ROC (31 août 2026) | PCI Security Standards Council (PCI SSC) | 2026-09-03 | International (industrie des paiements par carte) | Mise à jour de la FAQ 1331 du PCI Security Standards Council relative à l'utilisation des critères d'éligibilité SAQ dans les évaluations ROC (31 août 2026) | Le 31 août 2026, le PCI SSC a mis à jour la FAQ 1331, qui encadre l'utilisation des critères d'éligibilité aux Self-Assessment Questionnaires (SAQ) comme guide pour déterminer l'applicabilité des exigences PCI DSS lors des évaluations Report on Compliance (ROC). La version précédente permettait aux commerçants de s'appuyer sur leurs Qualified Security Assessors (QSA) pour appliquer ces critères et ainsi réduire le périmètre d'évaluation, le coût et la charge de conformité. La nouvelle version remplace l'essentiel de la FAQ par une directive nettement plus restrictive : les critères d'éligibilité SAQ ne doivent plus être utilisés comme « guide » pour déterminer l'applicabilité des exigences PCI DSS, sauf s'ils ont été explicitement examinés, discutés et approuvés par l'entité acceptant la conformité du commerçant (marques de paiement, acquéreurs). En pratique, tout ROC s'appuyant sur ces critères nécessite désormais l'approbation formelle de l'acquéreur, généralement communiquée par écrit à la société QSA. Sans cette approbation, les exclusions d'exigences précédemment justifiées par un SAQ correspondant pourraient ne plus être acceptées, entraînant des validations supplémentaires et des retards significatifs dans la réalisation des évaluations. De nouvelles précisions du PCI SSC sont attendues. | `hxxps://www[.]guidepointsecurity[.]com/blog/pci-dss-saq-elibigility-criteria/` |
| Amende de 500 000 € infligée par la CNIL à l'Hôpital privé de la Loire (Saint-Étienne, groupe Ramsay Santé) pour manquements au RGPD après une fuite de données concernant 727 113 personnes | CNIL (Commission Nationale de l'Informatique et des Libertés) | 2026-09-03 | France / Union européenne (RGPD) | Amende de 500 000 € infligée par la CNIL à l'Hôpital privé de la Loire (Saint-Étienne, groupe Ramsay Santé) pour manquements au RGPD après une fuite de données concernant 727 113 personnes | La CNIL a infligé une amende de 500 000 € à l'Hôpital privé de la Loire (HPL) à Saint-Étienne, établissement du groupe Ramsay Santé (650 salariés dont 180 médecins, 333 lits, environ 60 000 patients/an), pour des manquements aux articles 32 (sécurité du traitement) et 34 (notification des violations) du RGPD. La sanction fait suite à une intrusion à l'été 2025 ayant exposé les données sensibles de 727 113 personnes : 524 867 patients et 202 246 tiers de confiance. Un jeune pirate se présentant sous le pseudonyme « Marak » a revendiqué l'attaque auprès du journal Le Progrès via Telegram : le point d'entrée aurait été le compte d'un seul médecin, dont la compromission a permis d'accéder à l'ensemble du système interne ; les données auraient ensuite été proposées à la vente entre 2 000 et 5 000 € à un acheteur unique, sans être ni vendues ni publiées. La CNIL a relevé plusieurs défaillances techniques : accès au système depuis l'extérieur (notamment pour les médecins libéraux) sans VPN ni authentification multifacteur (MFA), contrôles d'accès insuffisants permettant à un compte compromis d'accéder aux dossiers de tous les patients, absence de supervision et d'alerte en temps réel ou quasi temps réel ayant permis à l'attaquant d'explorer le système et d'exfiltrer un volume massif de données pendant plusieurs jours sans détection, et notification incomplète (les patients ont été informés mais pas les 202 246 tiers de confiance). L'établissement a toutefois renforcé sa sécurité pendant la procédure. Cette sanction illustre le risque résiduel post-compromission d'identifiants valides lorsque les contrôles d'accès et la détection sont faibles. | `hxxps://mstdn[.]moimeme[.]ca/@EdwinG/117209435570886566`<br>`hxxps://osintsights[.]com/french-hospital-breach-fines-500000-for-gdpr-failures`<br>`hxxps://www[.]bleepingcomputer[.]com/news/security/french-hospital-fined-500-000-after-breach-exposes-data-of-727-000/`<br>`hxxps://www[.]franceinfo[.]fr/internet/securite-sur-internet/cyberattaques/une-clinique-privee-de-saint-etienne-sanctionnee-pour-des-manquements-apres-le-vol-de-donnees-de-500-000-patients_8175071.html` |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Santé (hôpital privé)** | Hôpital Privé de la Loire (HPL) | Données d'identité et de contact de 524 867 patients (dont des données de santé pour certains) et données de 202 246 personnes désignées comme « tiers de confiance » (proches de patients). | 727113 | [https://www.bleepingcomputer.com/news/security/french-hospital-fined-500-000-after-breach-exposes-data-of-727-000/](https://www.bleepingcomputer.com/news/security/french-hospital-fined-500-000-after-breach-exposes-data-of-727-000/)<br>[https://databreaches.net/2026/09/03/cnil-health-data-breach-e500000-fine-imposed-on-the-loire-private-hospital/](https://databreaches.net/2026/09/03/cnil-health-data-breach-e500000-fine-imposed-on-the-loire-private-hospital/) |
| **Secteur public / Justice (État du Dakota du Nord, États-Unis)** | Cour suprême du Dakota du Nord (North Dakota Supreme Court) | Non précisé dans la source (données détenues ou traitées par le prestataire tiers affecté). | Inconnu | [https://databreaches.net/2026/09/03/north-dakota-supreme-court-impacted-by-third-party-data-breach-that-has-affected-dozens-of-states/](https://databreaches.net/2026/09/03/north-dakota-supreme-court-impacted-by-third-party-data-breach-that-has-affected-dozens-of-states/) |
| **Services professionnels / Juridique (cabinets d'avocats américains principalement)** | Multiples cabinets d'avocats américains et autres entités (Katten Muchin Rosenman, Greenberg Traurig, Holland & Knight, Troutman Pepper Locke, Reminger, Riker Danzig, Rutan & Tucker, Fox Rothschild, Mayer Brown, etc.) | Non détaillé : données internes et données clients de cabinets d'avocats revendiquées, publication annoncée pour la plupart des entrées (statut « to be announced »). | Inconnu | [https://www.ransomlook.io//group/leakeddata](https://www.ransomlook.io//group/leakeddata) |
| **Santé** | Aesto Health | Numéros de Sécurité sociale (SSN), données personnelles et médicales de 9,5 millions de patients. | 9500000 | [https://infosec.exchange/@security_crawler_carl/117209462169056504](https://infosec.exchange/@security_crawler_carl/117209462169056504)<br>[https://theperimetersite.com/report/216](https://theperimetersite.com/report/216) |
| **Médias / Divertissement (streaming)** | Tving | Identifiants CI (Connecting Information), noms complets et ID utilisateurs, mots de passe chiffrés à sens unique (clés de chiffrement également volées), numéros de mobile, adresses e-mail, dates de naissance, ID intégrés CJ ONE, historiques de paiement, métadonnées de compte, ainsi que 361 projets de développement incluant code source, algorithmes de recommandation et systèmes d'authentification. | 40000000 | [https://theperimetersite.com/report/216](https://theperimetersite.com/report/216)<br>[https://theperimetersite.com/report/214](https://theperimetersite.com/report/214)<br>[https://infosec.exchange/@theperimetersite/117206883825729115](https://infosec.exchange/@theperimetersite/117206883825729115)<br>`hxxps://theperimetersite[.]com/report/214`<br>[https://beyondmachines.net/event_details/tving-data-breach-exposes-40-million-accounts-and-critical-source-code-y-4-i-j-0/gD2P6Ple2L](https://beyondmachines.net/event_details/tving-data-breach-exposes-40-million-accounts-and-critical-source-code-y-4-i-j-0/gD2P6Ple2L) |
| **Santé / Génétique médicale** | Baylor Genetics | Données personnelles d'environ 2,8 millions de personnes (détail non précisé ; le contexte génétique médical suggère des données de santé). | 2800000 | [https://theperimetersite.com/report/216](https://theperimetersite.com/report/216) |
| **Vérification d'identité / Scan de documents d'identité (clients : location de véhicules, dispensaires, logistique, retail, age verification)** | IDScan.net | Scans de permis de conduire (principalement américains et canadiens), cartes d'identité, documents de voyage, cartes médicales ; chaque document contient la date de naissance, l'adresse, les descriptions physiques et un numéro d'identification gouvernemental. Jusqu'à 170 millions de personnes potentiellement concernées. | 166579000 | [https://arstechnica.com/security/2026/09/my-drivers-license-is-one-of-153-million-for-sale-on-a-new-dark-website/](https://arstechnica.com/security/2026/09/my-drivers-license-is-one-of-153-million-for-sale-on-a-new-dark-website/)<br>[https://www.techdirt.com/2026/09/03/hackers-had-a-live-feed-of-every-id-this-verification-company-scanned-for-over-a-year/](https://www.techdirt.com/2026/09/03/hackers-had-a-live-feed-of-every-id-this-verification-company-scanned-for-over-a-year/)<br>[https://osintsights.com/drivers-licenses-exposed-in-massive-150m-record-breach?utm_source=mastodon&utm_medium=social](https://osintsights.com/drivers-licenses-exposed-in-massive-150m-record-breach?utm_source=mastodon&utm_medium=social)<br>[https://www.infosecurity-magazine.com/news/fbi-probes-breach-153-million/](https://www.infosecurity-magazine.com/news/fbi-probes-breach-153-million/) |
| **Cloud storage / Collaboration (vecteur : service d'identité tiers Lenovo ID)** | Dropbox (via faille Lenovo ID) | Contenus Dropbox (fichiers consultés et/ou téléchargés) d'environ 5 000 comptes ; moins d'un tiers des comptes ont fait l'objet d'un accès effectif aux fichiers. | 5000 | [https://hackread.com/hackers-accessed-dropbox-accounts-lenovo-id-flaw/](https://hackread.com/hackers-accessed-dropbox-accounts-lenovo-id-flaw/) |
| **Application mobile / Réseau social de pêche (loisirs)** | Fishbrain | Hachages de mots de passe, noms, adresses e-mail, numéros de téléphone (nombre d'utilisateurs concernés non quantifié dans les sources). | Inconnu | [https://osintsights.com/fishbrain-breach-exposes-password-hashes-to-cyberattack-risks?utm_source=mastodon&utm_medium=social](https://osintsights.com/fishbrain-breach-exposes-password-hashes-to-cyberattack-risks?utm_source=mastodon&utm_medium=social) |
| **Secteur public / Justice (éditeur de logiciels de gestion judiciaire)** | Thomson Reuters | Numéros de sécurité sociale, numéros de permis de conduire, informations médicales, informations d'assurance santé, dates de naissance, noms complets et dossiers judiciaires confidentiels, censurés ou sous scellés. | Inconnu | [https://osintsights.com/thomson-reuters-breach-exposes-us-and-canadian-court-records?utm_source=mastodon&utm_medium=social](https://osintsights.com/thomson-reuters-breach-exposes-us-and-canadian-court-records?utm_source=mastodon&utm_medium=social)<br>[https://beyondmachines.net/event_details/thomson-reuters-c-track-breach-exposes-data-across-multiple-state-court-systems-q-4-r-1-l/gD2P6Ple2L](https://beyondmachines.net/event_details/thomson-reuters-c-track-breach-exposes-data-across-multiple-state-court-systems-q-4-r-1-l/gD2P6Ple2L) |
| **Technologie / Vérification d'identité (KYC)** | IDScan.net (source présumée) – services de vérification d'identité US/Canada | Images haute résolution de permis de conduire et pièces d'identité gouvernementales (États-Unis et Canada), incluant vraisemblablement noms, dates de naissance, adresses et numéros de permis. | 153000000 | [https://theperimetersite.com/report/214](https://theperimetersite.com/report/214)<br>[https://infosec.exchange/@theperimetersite/117206883825729115](https://infosec.exchange/@theperimetersite/117206883825729115)<br>[https://newisty.com/blog/150-million-ids-allegedly-stolen-in-idscannet-breach-including-pete-hegseths-license?utm_source=social&utm_campaign=crypto_news](https://newisty.com/blog/150-million-ids-allegedly-stolen-in-idscannet-breach-including-pete-hegseths-license?utm_source=social&utm_campaign=crypto_news)<br>[https://mastodon.social/@newisty/117206829892011264](https://mastodon.social/@newisty/117206829892011264)<br>`hxxps://theperimetersite[.]com/report/214`<br>`hxxps://newisty[.]com/blog/150-million-ids-allegedly-stolen-in-idscannet-breach-including-pete-hegseths-license?utm_source=social&utm_campaign=crypto_news` |
| **Secteur public / Justice (éditeur de logiciels judiciaires)** | Thomson Reuters – West Publishing (plateforme C-Track) | Noms, numéros de Sécurité sociale (SSN), numéros de permis de conduire, dates de naissance, informations médicales et d'assurance santé ; numéros de dossier, noms/adresses/téléphones des parties, descriptions des chefs d'accusation et des entrées d'audience ; potentiellement des informations judiciaires confidentielles, rédigées ou scellées. | Inconnu | [https://thehackernews.com/2026/09/thomson-reuters-court-software-breach.html](https://thehackernews.com/2026/09/thomson-reuters-court-software-breach.html)<br>[https://infosec.exchange/@cloud/117208751645796631](https://infosec.exchange/@cloud/117208751645796631)<br>[https://infosec.exchange/@AAKL/117207894624760288](https://infosec.exchange/@AAKL/117207894624760288)<br>`hxxps://thehackernews[.]com/2026/09/thomson-reuters-court-software-breach.html`<br>`hxxps://infosec[.]exchange/@AAKL/117207894624760288` |
| **Immobilier / Gestion immobilière** | Castle Group (gestion immobilière, Plantation, Floride) | Noms complets, numéros de Sécurité sociale, dossiers de santé, codes de comptes financiers, informations de comptes crédit/débit, numéros d'identification gouvernementaux. | 47 | [https://beyondmachines.net/event_details/castle-group-ransomware-attack-exposes-sensitive-data-of-residents-m-8-q-p-u/gD2P6Ple2L](https://beyondmachines.net/event_details/castle-group-ransomware-attack-exposes-sensitive-data-of-residents-m-8-q-p-u/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117207943866066703](https://infosec.exchange/@beyondmachines1/117207943866066703)<br>`hxxps://beyondmachines[.]net/event_details/castle-group-ransomware-attack-exposes-sensitive-data-of-residents-m-8-q-p-u/gD2P6Ple2L` |
| **Santé / Oncologie** | Novocure (société d'oncologie) | Informations d'identification de moins de 50 patients (ouest des États-Unis), numéros d'identification patients internes pour plus de 1 400 patients US, coordonnées générales de prestataires de santé, coordonnées d'employés (titres de poste, téléphones). | 1450 | [https://beyondmachines.net/event_details/oncology-firm-novocure-discloses-data-breach-following-shinyhunters-extortion-claim-y-y-l-g-f/gD2P6Ple2L](https://beyondmachines.net/event_details/oncology-firm-novocure-discloses-data-breach-following-shinyhunters-extortion-claim-y-y-l-g-f/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117207471957822598](https://infosec.exchange/@beyondmachines1/117207471957822598)<br>`hxxps://beyondmachines[.]net/event_details/oncology-firm-novocure-discloses-data-breach-following-shinyhunters-extortion-claim-y-y-l-g-f/gD2P6Ple2L` |
| **Transport / Aéroportuaire** | Manchester Airports Group (MAG) | Données personnelles de 8,8 millions de personnes ; pour le secteur, typiquement numéros de passeport, manifests de vol/historique de voyage, coordonnées et détails de paiement (périmètre exact non confirmé par MAG). | 8800000 | [https://theperimetersite.com/report/215](https://theperimetersite.com/report/215)<br>[https://infosec.exchange/@theperimetersite/117208071364929698](https://infosec.exchange/@theperimetersite/117208071364929698)<br>`hxxps://theperimetersite[.]com/report/215` |
| **Non précisé dans la source (entreprise privée américaine)** | Central National Gottesman Inc. (CNG) | Noms complets et numéros de Sécurité sociale, numéros de permis de conduire et de passeport, numéros de comptes financiers et cartes de crédit, informations médicales et d'assurance santé, registres de paie, dates de naissance, contrats corporatifs et documents juridiques. | 1433 | [https://beyondmachines.net/event_details/central-national-gottesman-ransomware-attack-exposes-sensitive-data-s-1-x-a-h/gD2P6Ple2L](https://beyondmachines.net/event_details/central-national-gottesman-ransomware-attack-exposes-sensitive-data-s-1-x-a-h/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117208179772669470](https://infosec.exchange/@beyondmachines1/117208179772669470)<br>`hxxps://beyondmachines[.]net/event_details/central-national-gottesman-ransomware-attack-exposes-sensitive-data-s-1-x-a-h/gD2P6Ple2L` |
| **Santé / Sous-traitance et migration de données** | Aesto (société de migration de données de santé) | Données de santé sensibles et numéros de Sécurité sociale (SSN) pour plus de 9,5 millions de personnes. | 9500000 | [https://theperimetersite.com/report/214](https://theperimetersite.com/report/214)<br>[https://infosec.exchange/@theperimetersite/117206883825729115](https://infosec.exchange/@theperimetersite/117206883825729115)<br>`hxxps://theperimetersite[.]com/report/214` |
| **Santé / Distribution pharmaceutique** | McKesson | Dossiers de patients (revendiqués : dizaines de millions ; contenu exact et authenticité non confirmés). | Inconnu | [https://theperimetersite.com/report/214](https://theperimetersite.com/report/214)<br>[https://infosec.exchange/@theperimetersite/117206883825729115](https://infosec.exchange/@theperimetersite/117206883825729115)<br>`hxxps://theperimetersite[.]com/report/214` |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-20212** | 9.8 | N/A | FALSE | Commutateurs Cisco Nexus 9000 Series équipés d'un ASIC Silicon One exécutant NX-OS (45 releases affectées, de 10.3(1) à 10.6(3s)). Modèles concernés (PID) : N9324C-SE1U, N9348Y2C6D-SE1U, N9364E-SG2-O, N9364E-SG2-Q, N9396T12C-SE1, N9348Y12C-SE1, N9396Y12C-SE1, N9336C-SE1, N9K-C9804, N9K-C9808. Non affectés : les autres modèles Nexus 9000, les Nexus 9000 en mode ACI et les gammes Nexus 3000 et 7000. | Exécution de code arbitraire à distance avec privilèges root (ports TCP 43210/43211 exposés dans le VRF de couche 3 par défaut — liaison à une adresse IP non restreinte) | Compromission totale (privilèges root) de commutateurs de datacenter par un attaquant distant non authentifié : prise de contrôle de l'équipement, pivot réseau, interception ou manipulation du trafic. L'exploitation peut aussi provoquer un déni de service par crash du processus S1HAL et rechargement du commutateur. | Theoretical | Mettre à niveau vers une version corrective déterminée via le Cisco Software Checker (le bouclier Live Protect devient inutile à partir de NX-OS 10.6(4)) ; à défaut, déployer une iACL n'autorisant que les flux de gestion et de plan de contrôle requis ou bloquant explicitement les paquets TCP à destination des ports 43210/43211 ; déployer le bouclier temporaire Live Protect lp00031 (supporté sur NX-OS 10.6(3) et, via un second paquet, sur 10.6(3s) pour les deux Smart Switches ; non supporté sur N9K-C9804/9808 ; nécessite un accès SSH, Telnet ou NX-API) ; vérifier l'exposition via « show module » (PID). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1110/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1110/)<br>[https://thehackernews.com/2026/09/critical-cisco-nexus-9000-flaw-lets.html](https://thehackernews.com/2026/09/critical-cisco-nexus-9000-flaw-lets.html)<br>[https://www.security.nl/posting/951543/Cisco+dicht+kritiek+Nexus+9000-lek+dat+aanvaller+code+als+root+laat+uitvoeren?channel=rss](https://www.security.nl/posting/951543/Cisco+dicht+kritiek+Nexus+9000-lek+dat+aanvaller+code+als+root+laat+uitvoeren?channel=rss)<br>[https://securityaffairs.com/198366/security/cisco-fixed-critical-rce-in-nexus-9000-series-switches.html](https://securityaffairs.com/198366/security/cisco-fixed-critical-rce-in-nexus-9000-series-switches.html)<br>[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr)<br>[https://threatnoir.com/focus](https://threatnoir.com/focus)<br>[https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/](https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/) |
| **CVE-2026-20274** | 9.8 | N/A | FALSE | Cisco IOS XR Software — toutes les versions antérieures aux releases incluant les SMU (trains 6.9.x à 26.3.x cités par le CERT-FR, y compris IOS XR7/LNT) | CVE parapluie regroupant des défauts de sécurité mémoire et de gestion du cycle de vie des ressources (une CVE par catégorie CWE, notée au niveau du défaut le plus sévère de sa catégorie) | Selon le défaut exploité : exécution de code arbitraire à distance ou déni de service sur routeurs de cœur de réseau/opérateur exécutant IOS XR, avec un impact potentiellement critique sur la disponibilité et l'intégrité des infrastructures réseau. | Theoretical | Mettre à niveau IOS XR vers une release incluant les SMU puis appliquer ceux-ci (y compris pour les clients IOS XR7/LNT) ; se référer au bulletin cisco-sa-hardening-iosxr-qg64NcM ; aucun workaround n'est proposé par l'éditeur. | [https://thehackernews.com/2026/09/critical-cisco-nexus-9000-flaw-lets.html](https://thehackernews.com/2026/09/critical-cisco-nexus-9000-flaw-lets.html)<br>[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxr-qg64NcM](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxr-qg64NcM)<br>[https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/](https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/) |
| **CVE-2026-20279** | 9.8 | N/A | FALSE | Cisco IOS XR Software — toutes les versions antérieures aux releases incluant les SMU (trains 6.9.x à 26.3.x cités par le CERT-FR, y compris IOS XR7/LNT) | CVE parapluie regroupant des défauts de contrôle d'accès : authentification manquante pour des fonctions critiques et validation de certificats incorrecte | Accès non authentifié à des fonctions critiques du routeur ou contournement de la validation de certificats, pouvant conduire à une prise de contrôle de l'équipement, à des attaques de l'homme du milieu ou à la compromission du plan de contrôle. | Theoretical | Mettre à niveau IOS XR vers une release incluant les SMU puis appliquer ceux-ci (y compris pour les clients IOS XR7/LNT) ; se référer au bulletin cisco-sa-hardening-iosxr-qg64NcM ; aucun workaround n'est proposé par l'éditeur. | [https://thehackernews.com/2026/09/critical-cisco-nexus-9000-flaw-lets.html](https://thehackernews.com/2026/09/critical-cisco-nexus-9000-flaw-lets.html)<br>[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxr-qg64NcM](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxr-qg64NcM)<br>[https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/](https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/) |
| **CVE-2026-62911** | N/A | N/A | FALSE | Microsoft Exchange Server 2016, 2019 et Subscription Edition (SE) – environ 22 000 serveurs non corrigés | Contournement d'authentification (authentication bypass) | Détournement de l'ensemble des boîtes aux lettres utilisateurs sur les serveurs vulnérables : accès aux emails, vol de données, lancement de campagnes de phishing internes, compromission en chaîne via la réinitialisation de mots de passe d'autres services. | Theoretical | Identifier et corriger immédiatement toutes les instances Exchange 2016/2019/SE ; en parallèle, chasser les schémas d'authentification suspects et les anomalies d'accès aux boîtes aux lettres ; révoquer les sessions actives après patching. | [https://threatnoir.com/focus](https://threatnoir.com/focus) |
| **CVE-2026-20354** | N/A | N/A | FALSE | Cisco Secure Email – fonctionnalité de déchiffrement S/MIME, AsyncOS version 16.5.0 ou antérieure avec S/MIME activé | Validation insuffisante de l'intégrité des messages permettant une attaque de l'homme du milieu (MitM) / divulgation d'informations | Interception et modification du trafic entre passerelles email ; obtention du contenu en clair de communications censées être chiffrées par S/MIME ; atteinte à la confidentialité des échanges sensibles. | None | Surveiller les advisories Cisco et appliquer les correctifs AsyncOS dès publication ; en attendant, chiffrer et restreindre les liens inter-passarelles ; surveiller les échecs de validation d'intégrité S/MIME. | [https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/](https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/) |
| **CVE-2026-20355** | N/A | N/A | FALSE | Cisco Secure Email – fonctionnalité de déchiffrement S/MIME, AsyncOS version 16.5.0 ou antérieure avec S/MIME activé | Validation insuffisante de l'intégrité des messages permettant une attaque de l'homme du milieu (MitM) / divulgation d'informations | Interception et modification du trafic entre passerelles email ; divulgation du contenu en clair des communications chiffrées S/MIME. | None | Surveiller les advisories Cisco et appliquer les correctifs AsyncOS dès publication ; en attendant, chiffrer et restreindre les liens inter-passarelles ; surveiller les échecs de validation d'intégrité S/MIME. | [https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/](https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/) |
| **CVE-2026-20281** | N/A | N/A | FALSE | Cisco Desk Phone 9800, IP Phone 7800 et 8800, Video Phone 8875 (protocole SIP) | Déni de service (DoS) à distance non authentifié | Indisponibilité des services de téléphonie IP (terminaux inopérants), perturbation des communications vocales de l'organisation. | None | Appliquer les correctifs Cisco sur les terminaux affectés ; filtrer ou limiter le débit du trafic HTTP vers les téléphones ; segmenter le VLAN voix. | [https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/](https://www.securityweek.com/cisco-warns-of-unpatched-secure-email-flaws-patches-critical-switch-vulnerabilities/) |
| **CVE-2026-85053** | 8.8 | N/A | FALSE | Google Chrome versions antérieures à 152.0.7977.82 (composant CacheStorage) | Exposition inappropriée de ressources (CWE-668) menant à l'exécution de code arbitraire | Exécution de code arbitraire dans le sandbox du navigateur à l'ouverture d'une page web malveillante, pouvant servir de premier maillon d'une chaîne d'exploitation. | None | Mettre à jour Google Chrome vers la version 152.0.7977.82 ou ultérieure ; activer les mises à jour automatiques ; redémarrer le navigateur après mise à jour. Références : hxxps://chromereleases[.]googleblog[.]com/2026/09/stable-channel-update-for-desktop_01882797386[.]html et hxxps://issues[.]chromium[.]org/issues/552689418 | [https://cvefeed.io/vuln/detail/CVE-2026-85053](https://cvefeed.io/vuln/detail/CVE-2026-85053) |
| **CVE-2026-85051** | 8.8 | N/A | FALSE | Google Chrome versions antérieures à 152.0.7977.82 (composant Compositing) | Confusion de type (CWE-843) menant à l'exécution de code arbitraire | Exécution de code arbitraire dans le sandbox du navigateur à l'ouverture d'une page web malveillante. | None | Mettre à jour Google Chrome vers la version 152.0.7977.82 ; vérifier que le navigateur est à la dernière version ; activer les mises à jour automatiques. Références : hxxps://chromereleases[.]googleblog[.]com/2026/09/stable-channel-update-for-desktop_01882797386[.]html et hxxps://issues[.]chromium[.]org/issues/553449113 | [https://cvefeed.io/vuln/detail/CVE-2026-85051](https://cvefeed.io/vuln/detail/CVE-2026-85051) |
| **CVE-2026-85050** | 9.6 | N/A | FALSE | Google Chrome sur Android, versions antérieures à 152.0.7977.82 (composant WebGL) | Écriture hors limites (out-of-bounds write, CWE-787) menant à l'exécution de code arbitraire | Exécution de code arbitraire hors du sandbox du navigateur sur les terminaux Android, compromission potentiellement complète du terminal à l'ouverture d'une page web malveillante. | None | Mettre à jour Chrome sur Android vers la version 152.0.7977.82 ou ultérieure ; s'assurer que tous les composants sont à jour ; redémarrer le navigateur après mise à jour. Références : hxxps://chromereleases[.]googleblog[.]com/2026/09/stable-channel-update-for-desktop_01882797386[.]html et hxxps://issues[.]chromium[.]org/issues/549350408 | [https://cvefeed.io/vuln/detail/CVE-2026-85050](https://cvefeed.io/vuln/detail/CVE-2026-85050) |
| **CVE-2026-85049** | 8.8 | N/A | FALSE | Google Chrome versions antérieures à 152.0.7977.82 (bibliothèque graphique Skia) | Use-after-free (CWE-416) menant à l'exécution de code arbitraire | Exécution de code arbitraire dans le sandbox du navigateur à l'ouverture d'une page web malveillante. | None | Mettre à jour Google Chrome vers la version 152.0.7977.82 ou ultérieure ; s'assurer que tous les composants du navigateur sont à jour ; surveiller les prochains advisories de sécurité. Références : hxxps://chromereleases[.]googleblog[.]com/2026/09/stable-channel-update-for-desktop_01882797386[.]html et hxxps://issues[.]chromium[.]org/issues/553345874 | [https://cvefeed.io/vuln/detail/CVE-2026-85049](https://cvefeed.io/vuln/detail/CVE-2026-85049) |
| **CVE-2026-85048** | 8.3 | N/A | FALSE | Google Chrome versions antérieures à 152.0.7977.82 (composant Compositing) | Use-after-free (CWE-416) menant à l'exécution de code arbitraire hors sandbox | Exécution de code arbitraire hors du sandbox du navigateur (nécessite une compromission préalable du renderer), pouvant mener à la compromission du système hôte. | None | Mettre à jour Google Chrome vers la version 152.0.7977.82 ou ultérieure ; appliquer le correctif de sécurité ; redémarrer le navigateur. Références : hxxps://chromereleases[.]googleblog[.]com/2026/09/stable-channel-update-for-desktop_01882797386[.]html et hxxps://issues[.]chromium[.]org/issues/540357382 | [https://cvefeed.io/vuln/detail/CVE-2026-85048](https://cvefeed.io/vuln/detail/CVE-2026-85048) |
| **CVE-2026-85046** | 8.8 | N/A | FALSE | Google Chrome versions antérieures à 152.0.7977.82 (moteur JavaScript V8) | Confusion de type (CWE-843) menant à l'exécution de code arbitraire | Exécution de code arbitraire dans le sandbox du navigateur à l'ouverture d'une page web malveillante, pouvant servir de premier maillon d'une chaîne d'exploitation. | None | Mettre à jour Google Chrome vers la version 152.0.7977.82 ou ultérieure ; s'assurer que le moteur V8 est à jour ; éviter l'ouverture de pages HTML non fiables. Références : hxxps://chromereleases[.]googleblog[.]com/2026/09/stable-channel-update-for-desktop_01882797386[.]html et hxxps://issues[.]chromium[.]org/issues/542403045 | [https://cvefeed.io/vuln/detail/CVE-2026-85046](https://cvefeed.io/vuln/detail/CVE-2026-85046) |
| **CVE-2026-85042** | 9.6 | N/A | FALSE | Google Chrome versions antérieures à 152.0.7977.82 (composant DevTools) | Use-After-Free (CWE-416) | Exécution de code arbitraire hors sandbox sur le poste de la victime, contournement de l'isolation du navigateur et compromission potentielle complète du poste de travail. | None | Mettre à jour Google Chrome vers la version 152.0.7977.82 ou ultérieure (chromereleases.googleblog[.]com), appliquer le correctif éditeur et éviter d'ouvrir des pages HTML non fiables en attendant la mise à jour. | [https://cvefeed.io/vuln/detail/CVE-2026-85042](https://cvefeed.io/vuln/detail/CVE-2026-85042) |
| **CVE-2026-64197** | 8.5 | N/A | FALSE | DASYLab toutes versions antérieures à 2026.0.0 | Écriture hors limites (Out-of-bounds Write, CWE-787) | Exécution de code arbitraire ou plantage (déni de service) sur le poste analysant le fichier .DSB malveillant, avec impact sur les environnements d'acquisition et de mesure industrielle. | None | Mettre à jour DASYLab vers la version 2026.0.0 ou ultérieure et éviter d'ouvrir des fichiers .DSB non fiables. | [https://cvefeed.io/vuln/detail/CVE-2026-64197](https://cvefeed.io/vuln/detail/CVE-2026-64197) |
| **CVE-2026-64196** | 8.5 | N/A | FALSE | DASYLab toutes versions antérieures à 2026.0.0 | Écriture hors limites (Out-of-bounds Write, CWE-787) | Exécution de code arbitraire ou plantage (déni de service) sur le poste analysant le fichier .DSB malveillant. | None | Mettre à jour DASYLab vers la version 2026.0.0 ou ultérieure et éviter d'ouvrir des fichiers .DSB non fiables. | [https://cvefeed.io/vuln/detail/CVE-2026-64196](https://cvefeed.io/vuln/detail/CVE-2026-64196) |
| **CVE-2026-64195** | 8.5 | N/A | FALSE | DASYLab toutes versions antérieures à 2026.0.0 | Écriture hors limites (Out-of-bounds Write, CWE-787) | Exécution de code arbitraire ou plantage (déni de service) sur le poste analysant le fichier .DSB malveillant. | None | Mettre à jour DASYLab vers la version 2026.0.0 ou ultérieure et éviter d'ouvrir des fichiers .DSB non fiables. | [https://cvefeed.io/vuln/detail/CVE-2026-64195](https://cvefeed.io/vuln/detail/CVE-2026-64195) |
| **CVE-2026-83548** | 10.0 | N/A | TRUE | SonicWall SMA 1000 (série 6210 et modèles associés, matériel et virtuel) - composant Appliance Work Place | SSRF pré-authentification (Server-Side Request Forgery) | Accès non authentifié à des fonctionnalités sensibles de la passerelle d'accès distant, pivot vers l'exécution de commandes OS en combinaison avec CVE-2026-83549, compromission du périmètre et des accès distants. | Active | Appliquer en urgence les mises à jour de sécurité SonicWall pour les branches de firmware SMA 1000 concernées, restreindre l'exposition des interfaces d'administration, activer le MFA et surveiller les accès anormaux. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html)<br>[https://socprime.com/blog/cve-2026-83548-and-cve-2026-83549-analysis/](https://socprime.com/blog/cve-2026-83548-and-cve-2026-83549-analysis/) |
| **CVE-2026-83549** | 7.8 | N/A | TRUE | SonicWall SMA 1000 (mêmes branches de firmware que CVE-2026-83548) - composant Appliance Management Console | Injection de commandes OS post-authentification | Exécution de commandes arbitraires sur l'appliance (RCE), compromission de la passerelle d'accès distant, pivot possible vers le réseau interne. | Active | Appliquer en urgence les mises à jour de sécurité SonicWall pour SMA 1000, restreindre l'accès à la console de gestion, activer le MFA et surveiller les sessions administratives anormales. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html)<br>[https://socprime.com/blog/cve-2026-83548-and-cve-2026-83549-analysis/](https://socprime.com/blog/cve-2026-83548-and-cve-2026-83549-analysis/) |
| **CVE-2026-9586** | 9.3 | N/A | TRUE | Sangoma Switchvox | Injection SQL (avec RCE possible) | Exécution de code à distance sur le serveur de téléphonie IP, vol ou manipulation de données (enregistrements, annuaire, identifiants), déploiement de reverse shells pour mouvement ultérieur. | Active | Appliquer les correctifs Sangoma pour Switchvox, restreindre l'exposition du service et surveiller les requêtes SQL anormales et les connexions sortantes. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html) |
| **CVE-2026-82329** | 9.8 | N/A | TRUE | JFrog Artifactory (en configuration par défaut) | Authentification défaillante (obtention de privilèges administratifs non authentifiée) | Prise de contrôle administratif du registre d'artefacts, risque d'empoisonnement de la supply chain logicielle, vol d'identifiants et de secrets, mouvement latéral via les accès fédérés. | Active | Appliquer les correctifs JFrog, restreindre l'accès réseau à Artifactory, révoquer et rotater les jetons et secrets, auditer les comptes et tokens créés. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html) |
| **CVE-2026-48710** | 6.5 | N/A | TRUE | Kludex Starlette (framework ASGI Python) | HTTP request/response smuggling (injection de chemin dans la partie host) | Contournement d'authentification, accès non autorisé à des routes sensibles, et en chaîne avec CVE-2026-42271, exécution de code à distance sur les déploiements LiteLLM. | Active | Mettre à jour Starlette vers la version corrigée, ne pas fonder l'authentification sur le chemin d'URL reconstruit, déployer des règles WAF contre le smuggling et surveiller les requêtes à en-têtes Host ambigus. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html) |
| **CVE-2026-49869** | 10.0 | N/A | TRUE | Kestra OSS | Injection de commandes OS (création et exécution de workflows non authentifiées) | Exécution de code à distance non authentifiée, minage de cryptomonnaies (dégradation de ressources), vol de données et persistance via des workflows malveillants. | Active | Mettre à jour Kestra vers la version corrigée, ne pas exposer l'API publiquement, imposer une authentification forte, segmenter les environnements d'exécution et surveiller la création de workflows. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html) |
| **CVE-2026-59822** | 8.8 | N/A | TRUE | BerriAI LiteLLM - endpoint MCP (Model Context Protocol) Streamable HTTP | Authentification défaillante (session MCP établie avec un jeton Bearer arbitraire) | Accès non autorisé aux fonctionnalités MCP/LLM, énumération des modèles, abus potentiel des capacités du proxy LLM et des clés API configurées. | Active | Mettre à jour LiteLLM vers la version corrigée, restreindre l'exposition de l'endpoint MCP, imposer des jetons Bearer forts et rotater les clés API. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html) |
| **CVE-2026-42271** | 8.7 | N/A | TRUE | BerriAI LiteLLM | Vulnérabilité de LiteLLM (chaînable pour contournement d'authentification et RCE) | Contournement d'authentification, exécution de code à distance sur les déploiements LiteLLM, déploiement potentiel de ransomware par les affiliés Qilin avec double extorsion. | Active | Mettre à jour LiteLLM et Starlette vers les versions corrigées, restreindre l'exposition des services, surveiller les indicateurs Qilin et disposer de sauvegardes hors ligne. | [https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html](https://thehackernews.com/2026/09/cisa-adds-seven-exploited-flaws-as.html) |
| **CVE-2026-18329** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-33278** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-42959** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-63020** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-66362** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-66842** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-77180** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-78222** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-78689** | N/A | N/A | FALSE | Produits F5 : BIG-IP (17.1.x < 17.1.3.4 ; 17.5.x < 17.5.1.8 ; 21.0.x < 21.0.0.3 ; 21.1.x < 21.1.0.1), BIG-IP APM (17.1.x < 17.1.3.1 ; 17.5.x < 17.5.1.4), BIG-IQ (8.4.x < 8.4.2.1), NGINX Ingress Controller (2026-lts-rx < 2026-lts-r5 ; 5.x < 5.6.0), NGINX Gateway Fabric (2.x < 2.6.8), NGINX JavaScript (< 1.0.1), APM Clients (7.2.x < 7.2.6) - périmètre exact par CVE à confirmer dans les bulletins F5 | Non spécifié par l'éditeur pour cette CVE (l'avis couvre : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité/intégrité, contournement de politique de sécurité) | Selon la vulnérabilité : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, SSRF, atteinte à la confidentialité ou à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les correctifs F5 en migrant vers les versions listées dans l'avis CERT-FR (BIG-IP 17.1.3.4/17.5.1.8/21.0.0.3/21.1.0.1, BIG-IP APM 17.1.3.1/17.5.1.4, BIG-IQ 8.4.2.1, NGINX Ingress Controller 2026-lts-r5/5.6.0, NGINX Gateway Fabric 2.6.8, NGINX JavaScript 1.0.1, APM Clients 7.2.6) en se référant aux bulletins éditeur sur my[.]f5[.]com. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1111/) |
| **CVE-2026-85222** | 9.1 | N/A | FALSE | D-Link DNS-340L, firmware 1.01B04, composant Add-On Center (/cgi-bin/addon_center.cgi) | Injection de commandes OS (CWE-78/CWE-77) | Exécution de commandes arbitraires avec les privilèges du service web du NAS : compromission totale de l'équipement, vol ou chiffrement des données stockées (ransomware), pivot vers le réseau interne. | Theoretical | Mettre à jour le firmware D-Link vers la dernière version dès disponibilité ; restreindre l'accès à l'interface d'administration et au composant Add-On Center (VPN, réseau de gestion) ; surveiller le trafic vers /cgi-bin/addon_center.cgi ; en l'absence de correctif, ne pas exposer le NAS sur Internet et désactiver Add-On Center. | [https://cvefeed.io/vuln/detail/CVE-2026-85222](https://cvefeed.io/vuln/detail/CVE-2026-85222)<br>[https://vuldb.com/cve/CVE-2026-85222](https://vuldb.com/cve/CVE-2026-85222)<br>[https://github.com/dxz0069/WAVLINK-WN530H4-Command-Injection-in-set_add_routing/blob/main/DLINK-CMD-007-vulndb.md](https://github.com/dxz0069/WAVLINK-WN530H4-Command-Injection-in-set_add_routing/blob/main/DLINK-CMD-007-vulndb.md) |
| **CVE-2026-85061** | 10.0 | N/A | FALSE | MapLibre GL JS, toutes versions antérieures à 6.4.1 | Cross-Site Scripting par contournement de sanitization DOM (CWE-79) | Exécution de JavaScript dans le navigateur de la victime (XSS DOM) : vol de cookies/jetons de session, actions au nom de l'utilisateur, défacement de la carte, redirection vers des pages malveillantes. | Theoretical | Mettre à jour MapLibre GL JS vers 6.4.1 ou ultérieure ; ne pas rendre de HTML non fiable dans les attributions de carte ; assainir tout contenu HTML externe côté serveur ; appliquer une CSP stricte. | [https://cvefeed.io/vuln/detail/CVE-2026-85061](https://cvefeed.io/vuln/detail/CVE-2026-85061)<br>[https://github.com/maplibre/maplibre-gl-js/security/advisories/GHSA-jrc7-96c5-q579](https://github.com/maplibre/maplibre-gl-js/security/advisories/GHSA-jrc7-96c5-q579)<br>[https://github.com/maplibre/maplibre-gl-js/releases/tag/v6.4.1](https://github.com/maplibre/maplibre-gl-js/releases/tag/v6.4.1) |
| **CVE-2026-82520** | 8.7 | N/A | FALSE | parsedmarc, toutes versions antérieures à 11.0.1 | Déni de service par amplification de données / zip bomb (CWE-409) | Déni de service par épuisement mémoire (OOM) du processus parsedmarc, interruption du traitement des rapports DMARC, impact potentiel sur l'hôte hébergeant d'autres services. | Theoretical | Mettre à jour parsedmarc vers 11.0.1 ou ultérieure ; configurer des limites de décompression et de taille des pièces jointes ; superviser la consommation mémoire ; filtrer les archives à fort ratio de compression. | [https://cvefeed.io/vuln/detail/CVE-2026-82520](https://cvefeed.io/vuln/detail/CVE-2026-82520)<br>[https://github.com/domainaware/parsedmarc/security/advisories/GHSA-43qf-f35w-2x4r](https://github.com/domainaware/parsedmarc/security/advisories/GHSA-43qf-f35w-2x4r)<br>[https://www.vulncheck.com/advisories/parsedmarc-zip-bomb-dos-via-compressed-email-attachments](https://www.vulncheck.com/advisories/parsedmarc-zip-bomb-dos-via-compressed-email-attachments) |
| **CVE-2026-63376** | 8.2 | N/A | FALSE | toml-node, toutes versions antérieures à 4.1.2 (Node.js et navigateur) | Pollution de prototype (CWE-1321) | Propriétés injectées visibles dans tout le processus Node.js : déni de service, contournement de logique ou d'autorisation, voire exécution de code si l'application contient un gadget exploitable. | Theoretical | Mettre à jour toml-node vers 4.1.2 ou ultérieure ; auditer les dépendances pour identifier les versions vulnérables ; surveiller les avis de sécurité ; ajouter des tests couvrant les entrées __proto__. | [https://cvefeed.io/vuln/detail/CVE-2026-63376](https://cvefeed.io/vuln/detail/CVE-2026-63376)<br>[https://github.com/BinaryMuse/toml-node/security/advisories/GHSA-v5mp-jgw5-2x6j](https://github.com/BinaryMuse/toml-node/security/advisories/GHSA-v5mp-jgw5-2x6j)<br>[https://github.com/BinaryMuse/toml-node](https://github.com/BinaryMuse/toml-node) |
| **CVE-2026-85047** | N/A | N/A | FALSE | Google Chrome — Transactions Platform (versions non précisées dans la source) | Validation d'entrée incorrecte (CWE-20) | Non déterminé faute de détails ; une validation d'entrée défaillante dans un composant de transactions pourrait permettre un comportement inattendu côté navigateur (manipulation de transactions, contournement de contrôles). | None | Maintenir Chrome à jour via le canal stable et la mise à jour automatique ; appliquer dès publication le correctif mentionné pour CVE-2026-85047 ; surveiller les avis Google Chrome Releases et les bases de vulnérabilités. | [https://cvefeed.io/vuln/detail/CVE-2026-85047](https://cvefeed.io/vuln/detail/CVE-2026-85047) |
| **CVE-2026-82527** | 8.7 | N/A | FALSE | R2R (SciPhi-AI), toutes versions jusqu'à 3.6.6 incluses | Injection SQL (CWE-89) | Exfiltration du contenu de la base applicative (documents, embeddings, métadonnées, potentiellement identifiants), contournement de la logique métier d'un pipeline RAG, atteinte possible à la confidentialité des données indexées. | Theoretical | Paramétrer toutes les requêtes SQL ; valider les clés de filtre par liste blanche ; restreindre les privilèges du compte base de données ; déployer des règles WAF ; appliquer le correctif éditeur dès sa disponibilité. | [https://cvefeed.io/vuln/detail/CVE-2026-82527](https://cvefeed.io/vuln/detail/CVE-2026-82527)<br>[https://www.vulncheck.com/advisories/r2r-sql-injection-via-retrieval-search-filter-key](https://www.vulncheck.com/advisories/r2r-sql-injection-via-retrieval-search-filter-key)<br>[https://github.com/SciPhi-AI/R2R/issues/2308](https://github.com/SciPhi-AI/R2R/issues/2308) |
| **CVE-2026-44506** | N/A | N/A | FALSE | Medplum, déploiements auto-hébergés (self-hosted) avec enregistrement dynamique de clients OAuth (versions non précisées dans la source) | Exposition d'informations sensibles (secret client OAuth via endpoint d'enregistrement dynamique) | Un attaquant pourrait obtenir un secret client OAuth et accéder aux ressources FHIR/données de santé au nom d'un client légitime, avec un risque élevé de fuite de données sensibles et d'usurpation d'application. | None | Restreindre ou désactiver l'enregistrement dynamique de clients OAuth si non nécessaire ; faire tourner les secrets clients ; révoquer les jetons émis ; appliquer le correctif Medplum dès publication ; auditer les clients OAuth enregistrés. | [https://cvefeed.io/vuln/detail/CVE-2026-44506](https://cvefeed.io/vuln/detail/CVE-2026-44506) |
| **CVE-2026-85396** | 8.7 | N/A | FALSE | rubyzip, toutes versions antérieures à 3.4.0 (Zip::Entry#extract) | Traversée de chemin / Path Traversal (CWE-22) | Écriture arbitraire de fichiers hors du répertoire cible, potentiellement dans des emplacements exécutables : exécution de code, persistance, écrasement de fichiers sensibles lors du traitement d'archives non fiables. | Theoretical | Mettre à jour rubyzip vers 3.4.0 ou ultérieure ; valider les chemins d'extraction (normalisation, gestion des séparateurs) ; assainir les noms d'entrées d'archive ; éviter l'extraction automatique d'archives non fiables ; surveiller les écritures de fichiers anormales. | [https://cvefeed.io/vuln/detail/CVE-2026-85396](https://cvefeed.io/vuln/detail/CVE-2026-85396)<br>[https://www.vulncheck.com/advisories/rubyzip-before-3.4.0-path-traversal-in-zip-entry-extract-via-sibling-directory-prefix](https://www.vulncheck.com/advisories/rubyzip-before-3.4.0-path-traversal-in-zip-entry-extract-via-sibling-directory-prefix)<br>[https://github.com/rubyzip/rubyzip/commit/17edfbf4423b83211b075acc23a7d8640da63449](https://github.com/rubyzip/rubyzip/commit/17edfbf4423b83211b075acc23a7d8640da63449) |
| **CVE-2026-32475** | N/A | N/A | FALSE | Elementor Pro (plugin page builder WordPress), versions antérieures à 4.2.2 — estimé déployé sur environ 6 millions de sites | Upload de fichiers arbitraire (contournement de validation d'extension via nom de fichier vide) menant à l'exécution de code à distance | Prise de contrôle totale des sites WordPress vulnérables : exécution de code à distance via PHP, installation de backdoors, création de comptes administrateur, compromission des données du site et utilisation comme relais d'attaques. | Active | Mettre à jour Elementor Pro vers la version 4.2.2 ou supérieure sans délai ; auditer les sites ayant eu le plugin exposé avec un formulaire à upload ; déployer un WAF ; rechercher fichiers PHP suspects, comptes admin frauduleux et backdoors sur les sites restés vulnérables après le 19 août. | [https://www.security.nl/posting/951567/WordPress-sites+aangevallen+via+kritiek+upload-lek+in+Elementor+Pro?channel=rss](https://www.security.nl/posting/951567/WordPress-sites+aangevallen+via+kritiek+upload-lek+in+Elementor+Pro?channel=rss) |
| **CVE-2026-59346** | 9.3 | N/A | FALSE | VMware Workstation et VMware Fusion (hyperviseurs de bureau) — faille dans l'adaptateur réseau virtuel VMXNET3 | Integer overflow dans l'adaptateur réseau virtuel VMXNET3 permettant l'exécution de code sur l'hôte depuis une machine virtuelle (VM escape) | Évasion de machine virtuelle : exécution de code sur l'hôte hyperviseur, compromission de la machine hôte et accès potentiel aux autres VM hébergées et au réseau interne. | None | Installer les mises à jour VMware Workstation/Fusion publiées par Broadcom ; en attendant, retirer l'adaptateur VMXNET3 des VM à risque ou restreindre les droits administrateur dans les invités. | [https://www.security.nl/posting/951602/Kritieke+VMware-kwetsbaarheid+laat+vm-aanvaller+code+op+host+uitvoeren?channel=rss](https://www.security.nl/posting/951602/Kritieke+VMware-kwetsbaarheid+laat+vm-aanvaller+code+op+host+uitvoeren?channel=rss) |
| **CVE-2026-85394** | 9.3 | N/A | FALSE | python-jose (bibliothèque Python JOSE/JWT), toutes versions jusqu'à 3.5.0 incluses | Confusion d'algorithme / vérification cryptographique incorrecte (CWE-347) : acceptation de clés asymétriques encodées DER lors de l'initialisation HMAC | Contournement d'authentification et usurpation d'identité via des JWT forgés pour toute application utilisant python-jose avec vérification HMAC et clé publique accessible à l'attaquant. | Theoretical | Mettre à jour python-jose vers une version corrigée ; restreindre explicitement les algorithmes autorisés ; valider les formats d'encodage des clés ; limiter l'exposition de la clé publique de signature. | [https://cvefeed.io/vuln/detail/CVE-2026-85394](https://cvefeed.io/vuln/detail/CVE-2026-85394)<br>[https://www.vulncheck.com/advisories/python-jose-through-3.5.0-algorithm-confusion-via-der-encoded-public-key-as-hmac-secret](https://www.vulncheck.com/advisories/python-jose-through-3.5.0-algorithm-confusion-via-der-encoded-public-key-as-hmac-secret) |
| **CVE-2026-85393** | 8.7 | N/A | FALSE | node-forge (bibliothèque cryptographique JavaScript), toutes versions jusqu'à 1.4.0 incluses | Falsification de signature RSA PKCS#1 v1.5 via remplissage de séquences DigestAlgorithm imbriquées (CWE-347) | Usurpation de signatures cryptographiques (certificats, jetons, mises à jour signées) auprès des applications Node.js s'appuyant sur node-forge, avec risque de contournement de contrôles d'intégrité et d'authentification. | Theoretical | Mettre à jour node-forge au-delà de la version 1.4.0 ; valider le nombre d'éléments dans les séquences imbriquées ; garantir une vérification RSA PKCS#1 v1.5 conforme ; privilégier des clés à exposant élevé ou RSA-PSS. | [https://cvefeed.io/vuln/detail/CVE-2026-85393](https://cvefeed.io/vuln/detail/CVE-2026-85393)<br>[https://www.vulncheck.com/advisories/node-forge-through-1.4.0-rsa-pkcs-1-1.5-signature-forgery-via-nested-digestalgorithm-padding](https://www.vulncheck.com/advisories/node-forge-through-1.4.0-rsa-pkcs-1-1.5-signature-forgery-via-nested-digestalgorithm-padding)<br>[https://github.com/advisories/GHSA-ppp5-5v6c-4jwp](https://github.com/advisories/GHSA-ppp5-5v6c-4jwp) |
| **CVE-2026-84115** | N/A | N/A | FALSE | Cleo Harmony (plateforme de transfert de fichiers géré / MFT) | Faille dans le gestionnaire de jetons de rafraîchissement JWT exposant à un risque d'attaque à distance (détails techniques limités dans la source) | Risque d'accès distant non autorisé et de compromission de sessions sur une plateforme d'échange de fichiers, avec potentiel d'exfiltration de données sensibles transitant par la solution MFT. | Theoretical | Appliquer les correctifs Cleo dès disponibilité ; restreindre l'exposition Internet de la plateforme ; imposer le MFA ; surveiller les jetons de rafraîchissement anormaux et les transferts atypiques. | [https://thecyberexpress.com/cve-2026-84115-cleo-harmony-jwt-refresh-token/](https://thecyberexpress.com/cve-2026-84115-cleo-harmony-jwt-refresh-token/) |
| **CVE-2026-15933** | N/A | N/A | FALSE | OptimiDoc Server (édition on-premise, solution de gestion d'impression) | Vulnérabilité non détaillée dans la source (type, score CVSS et conditions d'exploitation à consulter dans l'avis CERT.pl) | Non précisé dans la source ; à évaluer selon l'avis CERT.pl (les serveurs d'impression on-premise exposés peuvent constituer des points d'entrée vers le réseau interne). | None | Consulter l'avis CERT.pl et appliquer les correctifs/atténuations recommandés par l'éditeur ; restreindre l'exposition réseau du serveur OptimiDoc en attendant. | [https://cert.pl/en/posts/2026/09/CVE-2026-15933/](https://cert.pl/en/posts/2026/09/CVE-2026-15933/) |
| **CVE-2026-69414** | N/A | N/A | FALSE | Microsoft Defender (antivirus/protection Microsoft Defender sur Windows) | Élévation de privilèges locale zéro-day (PoC « ShieldBreak ») permettant l'exécution de code avec les privilèges NT AUTHORITY\SYSTEM — évaluée comme un contournement du correctif de CVE-2026-50656 (RoguePlanet) | Élévation de privilèges locale jusqu'à SYSTEM, permettant la persistance, l'affaiblissement des défenses (exclusions Defender) et la compromission complète du poste. | Theoretical | Appliquer le correctif Microsoft dès sa publication ; surveiller les écritures de DLL dans System32 par des processus signés ; restreindre les privilèges locaux ; déployer des détections Sysmon/EDR sur les tâches Windows Error Reporting et les manipulations d'Object Manager. | [https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html](https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html) |
| **CVE-2026-50656** | N/A | N/A | FALSE | Microsoft Defender (antivirus/protection Microsoft Defender sur Windows) | Élévation de privilèges locale (alias « RoguePlanet ») — ShieldBreak (CVE-2026-69414) est évalué comme un contournement de son correctif | Élévation de privilèges locale via Microsoft Defender ; le contournement de correctif par ShieldBreak maintient le risque d'exécution de code en SYSTEM sur les postes à jour. | None | Maintenir Microsoft Defender et la plateforme Windows à jour ; surveiller les avis MSRC concernant le contournement ; déployer des détections sur les techniques d'élévation de privilèges via le moteur de remédiation. | [https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html](https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html) |
| **CVE-2026-85012** | N/A | N/A | FALSE | Paquet npm @amazon-codecatalyst/blueprints.blueprint, versions <= 0.3.155 (framework de resynthèse des blueprints Amazon CodeCatalyst) | Injection de commandes OS (CWE-78) | Exécution de commandes arbitraires dans l'environnement de resynthèse avec les privilèges et identifiants disponibles dans cet environnement, pouvant conduire au vol d'identifiants CI/CD, à la manipulation de projets logiciels ou à la compromission de la chaîne d'approvisionnement logicielle. Les consommateurs directs du paquet npm sont exposés ; le service CodeCatalyst managé n'est pas affecté. | None | Mettre à jour vers la version 0.3.156 ou ultérieure du paquet @amazon-codecatalyst/blueprints.blueprint : cette version supprime l'interprétation shell du champ owner (exécution directe sans shell) et rejette les valeurs hors forme allowlist. La mise à jour est la seule mitigation pour les consommateurs directs du paquet, le fichier .ownership-file activant la stratégie concernée sans configuration. S'assurer que tout fork ou code dérivé intègre les correctifs. Aucune action n'est requise pour l'utilisation du service Amazon CodeCatalyst. | [https://aws.amazon.com/security/security-bulletins/rss/2026-095-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-095-aws/) |
| **CVE-2026-85028** | N/A | N/A | FALSE | AWS FPGA Developer Kit (aws-fpga), versions < 2.3.4 (composant d'installation de l'outil de gestion FPGA) | Création de fichier temporaire dans un répertoire aux permissions non sécurisées (CWE-378) menant à une élévation de privilèges locale | Élévation de privilèges locale à root sur les machines où le SDK est installé, permettant à un attaquant ayant déjà un accès local (compte à faibles privilèges) d'obtenir un contrôle total du système : exécution de code arbitraire en tant que root, installation de mécanismes de persistance, accès aux données et aux accélérateurs FPGA. | None | Mettre à jour l'AWS FPGA Developer Kit vers la version 2.3.4 ou ultérieure : le code écrivant la fonction allow_non_root dans /tmp/sdk_root_env.exp a été supprimé et les outils du SDK sourcent désormais ces fonctions directement depuis shared/bin/set_common_functions.sh. En attendant, appliquer le contournement consistant à supprimer ou commenter les lignes référençant /tmp/sdk_root_env.exp dans sdk_setup.sh et install_fpga_mgmt_tools.sh. S'assurer que tout fork ou code dérivé intègre les correctifs. | [https://aws.amazon.com/security/security-bulletins/rss/2026-096-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-096-aws/) |
| **** | N/A | N/A | FALSE | SPIP versions antérieures à 4.4.23 | Multiples vulnérabilités (exécution de code arbitraire à distance, élévation de privilèges) | Compromission complète du serveur hébergeant le CMS : exécution de code à distance, prise de contrôle administratif de SPIP, pivot possible vers l'infrastructure hébergeant le site. | None | Mettre à jour SPIP vers la version 4.4.23 ou ultérieure en se référant au bulletin éditeur (blog.spip[.]net - Mise à jour critique de sécurité, sortie de SPIP 4.4.23). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1109/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1109/) |
| **** | N/A | N/A | FALSE | SonicWall SMA1000 (appliance d'accès distant sécurisé / SSL-VPN) | Deux vulnérabilités zéro-day activement exploitées, dont une de sévérité maximale — identifiants CVE et détails techniques non divulgués dans la source | Compromission potentielle d'appliances d'accès distant exposées : accès non authentifié au réseau interne, vol d'identifiants, déploiement de persistance en amont de l'infrastructure. | Active | Suivre l'avis SonicWall et appliquer les correctifs dès publication ; restreindre l'exposition Internet des interfaces SMA1000 ; imposer le MFA ; surveiller activement les journaux d'authentification et d'administration. | [https://thecyberexpress.com/sonicwall-warns-of-two-zero-days-in-sma1000/](https://thecyberexpress.com/sonicwall-warns-of-two-zero-days-in-sma1000/) |
| **** | N/A | N/A | FALSE | CrowdStrike Falcon Sensor (Windows), testé sur Windows 11 25H2 à jour et Windows Server 2025 | Élévation de privilèges locale zéro-day (PoC public « FalconFlank ») abusant de la fonction de remédiation des macros Office malveillantes — aucune CVE attribuée à ce stade | Élévation de privilèges locale en contournant l'agent EDR, permettant à un attaquant ayant un accès local d'exécuter des actions malveillantes avec des privilèges accrus tout en évitant la détection. | Theoretical | Appliquer les mises à jour et atténuations CrowdStrike dès publication ; auditer et réduire les exclusions EDR ; surveiller les abus de la fonction de remédiation de macros ; restreindre les privilèges locaux ; valider les détections sur les versions récentes de Windows. | [https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html](https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html) |
| **** | N/A | N/A | TRUE | Non spécifié - l'article ne détaille ni les produits ni les identifiants CVE des 7 vulnérabilités ajoutées au catalogue KEV | Multiples vulnérabilités activement exploitées (inscription au catalogue KEV) | Risque élevé de compromission pour toute organisation exposée n'ayant pas corrigé ces failles : l'exploitation active documentée par la CISA implique une probabilité de compromission significative en l'absence de correctif ou de mesure compensatoire. | Active | Consulter le catalogue KEV officiel de la CISA pour identifier les 7 vulnérabilités concernées, prioriser leur correction selon les échéances (due dates) fixées par la CISA (généralement 2 à 3 semaines), appliquer les correctifs en priorité sur les systèmes exposés à Internet et déployer des mesures compensatoires lorsque le patching est impossible. | [https://thecyberthrone.in/2026/09/03/cisa-adds-7-vulnerabilities-to-kev-a-new-wave-of-actively-exploited-flaws/](https://thecyberthrone.in/2026/09/03/cisa-adds-7-vulnerabilities-to-kev-a-new-wave-of-actively-exploited-flaws/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="ascii-smuggling-de-linjection-de-prompt-ia-a-levasion-anti-phishing"></div>

## ASCII smuggling : de l'injection de prompt IA à l'évasion anti-phishing

### Résumé

Microsoft (Security Blog, 3 septembre 2026) rapporte que la technique d'« ASCII smuggling », jusqu'ici associée aux attaques par injection de prompt contre les assistants IA, est désormais détournée à des fins d'évasion dans des campagnes de phishing. La technique repose sur des caractères ASCII/Unicode invisibles permettant de dissimuler des contenus malveillants (liens, instructions) aux filtres comme à l'utilisateur. Le même article signale deux autres campagnes actives suivies par Microsoft Threat Intelligence : une intrusion opérée par un humain qui abuse de la collaboration externe Microsoft Teams pour se faire passer pour le support IT, obtenir un accès distant et déployer un malware basé sur Node ; et une campagne d'installateurs contrefaits imitant des éditeurs logiciels légitimes au moyen de pages de téléchargement look-alike et d'archives d'installation régénérées.

---

### Analyse opérationnelle

Les équipes SOC doivent étendre l'inspection de contenu des e-mails à la détection de caractères invisibles (zero-width, tags Unicode) et prévoir des procédures de décodage/reconstruction des contenus smugglés. La vérification hors bande des demandes de support IT et le contrôle des accès distants accordés via Teams constituent des points de contrôle prioritaires. Pour la chaîne de distribution logicielle, la validation par hash/signature des installateurs et le blocage des pages look-alike réduisent l'exposition à la campagne d'installateurs contrefaits.

---

### Implications stratégiques

Cette évolution illustre la migration de techniques nées dans l'écosystème IA (injection de prompt) vers le cybercrime classique, brouillant la frontière entre sécurité IA et sécurité e-mail. Elle fragilise la confiance dans les canaux de collaboration légitimes (Teams) et dans la distribution logicielle, et impose d'intégrer les assistants IA et les outils de collaboration dans le périmètre de la politique de sécurité de l'organisation.

---

### Recommandations

* Activer la détection/normalisation des caractères Unicode invisibles sur les passerelles de messagerie
* Imposer une validation hors bande de toute demande de support IT sollicitant un accès distant
* Restreindre et journaliser la collaboration externe Microsoft Teams
* Vérifier hash et signature électronique des installateurs avant déploiement
* Sensibiliser les utilisateurs à l'existence de contenus e-mail invisibles dissimulant des liens malveillants

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs et les analystes à la technique d'ASCII smuggling (caractères zero-width, tags Unicode, espaces invisibles)
* Configurer les passerelles de messagerie et les proxys pour signaler ou normaliser les séquences de caractères invisibles
* Définir une procédure de vérification des demandes de support IT entrantes (canal officiel, validation hors bande)
* Mettre en place une liste blanche de sources et un contrôle d'intégrité (hash, signature) pour les installateurs logiciels distribués en interne

#### Phase 2 — Détection et analyse

* Inspecter les e-mails et documents pour détecter des séquences de caractères ASCII/Unicode invisibles encodant des URL ou des commandes
* Alerter sur les demandes d'accès distant non sollicitées se réclamant du support IT via Microsoft Teams ou la collaboration externe
* Surveiller l'installation d'exécutables ou de scripts Node provenant de pages de téléchargement look-alike ou d'archives régénérées
* Corréler les interactions avec des assistants IA et des contenus e-mail suspects

#### Phase 3 — Confinement, éradication et récupération

* Mettre en quarantaine les messages contenant du contenu smugglé et purger les campagnes des boîtes de tous les destinataires
* Bloquer les domaines et URL extraits des contenus décodés
* Révoquer les sessions Teams et accès distants accordés à des opérateurs usurpant le support IT
* Isoler les hôtes ayant exécuté des installateurs non validés et réinitialiser les identifiants des utilisateurs concernés

#### Phase 4 — Activités post-incident

* Reconstruire les contenus ASCII smugglés pour extraire les charges utiles et documenter les IOC
* Analyser les implants déployés (notamment les outils basés sur Node) et déterminer l'étendue de l'accès obtenu
* Mettre à jour les règles de détection de messagerie et partager les indicateurs avec la communauté/le CERT
* Revoir les paramètres de collaboration externe Teams (restrictions, approbation des domaines externes)

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans les journaux de messagerie les messages contenant des caractères de contrôle/whitespace Unicode anormaux
* Rechercher les sessions Teams d'assistance non planifiées ayant débouché sur des outils de prise en main à distance
* Identifier les téléchargements d'installateurs dont le hash ne correspond pas à la distribution officielle de l'éditeur
* Surveiller les requêtes vers des pages de téléchargement look-alike imitant des éditeurs logiciels légitimes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing : usage d'ASCII smuggling pour dissimuler des contenus malveillants dans des messages et échapper aux filtres |
| **T1027** | Obfuscated Files or Information : dissimulation de liens/commandes via des caractères ASCII/Unicode invisibles |

---

### Sources

* [https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)


---

<div id="tendances-malware-et-vulnerabilites-du-s1-2026-labus-doutils-legitimes-au-cur-des-intrusions"></div>

## Tendances malware et vulnérabilités du S1 2026 : l'abus d'outils légitimes au cœur des intrusions

### Résumé

Dans son rapport publié le 3 septembre 2026, l'Insikt Group de Recorded Future dresse le bilan du S1 2026 : 215 CVE activement exploitées ont été identifiées, en hausse de 34 % par rapport aux 161 du S1 2025 ; 142 des 146 vulnérabilités exploitables sans authentification préalable étaient également accessibles via le réseau, et 60 des 82 vulnérabilités d'exécution de code à distance (RCE) combinaient accès réseau et absence d'authentification. Les acteurs ont privilégié l'abus d'outils légitimes, de plateformes de confiance et de flux de travail routiniers (logiciels exposés, outils de développement, utilitaires d'accès à distance, flux de paiement, services tiers) plutôt que la nouveauté technique. Les RAT demeurent en tête de l'activité malware. Les capacités activées par l'IA sont restées majoritairement additives à la tradecraft existante, alignées sur les niveaux bas à intermédiaires du modèle AIM3 de Recorded Future (persistance, interaction UI, développement et livraison de malware), tandis que la recherche assistée par IA accroît le volume de rapports de vulnérabilités. Sont également documentées des compromissions de chaîne d'approvisionnement visant gestionnaires de paquets et environnements développeurs (y compris l'outillage IA), des malwares mobiles permettant une fraude de paiement par abus NFC, et des campagnes Magecart exploitant des services tiers de confiance et la manipulation du checkout.

---

### Analyse opérationnelle

Les équipes doivent prioriser la remédiation des vulnérabilités exploitables à distance et permettant l'exécution de code, l'exposition et l'impact étant des indicateurs de risque opérationnel plus fiables que le classement éditeur ou le score de sévérité seul. La détection doit porter sur des séquences de comportements (exécution, obfuscation, découverte, transfert de payload) plutôt que sur des événements isolés, y compris lorsque l'activité emprunte des outils approuvés. Des contrôles spécifiques sont attendus sur les identifiants développeurs, l'infrastructure de sauvegarde, les appareils mobiles d'entreprise et les environnements de paiement.

---

### Implications stratégiques

La progression de 34 % des CVE activement exploitées et l'accélération potentielle de l'analyse des chemins d'exploitation par l'IA laissent présager une compression des délais de remédiation, obligeant les organisations à industrialiser la gestion d'exposition et la gouvernance des identifiants. La stratégie d'évasion par la normalité (outils légitimes, services de confiance) accroît le risque que des intrusions aboutissent avant détection, avec des conséquences directes sur les budgets de détection comportementale, la supervision des tiers et la résilience des sauvegardes.

---

### Recommandations

* Prioriser les CVE combinant accessibilité réseau, absence d'authentification et RCE
* Déployer des détections comportementales couvrant les séquences d'intrusion via des outils légitimes
* Renforcer MFA et gestion des secrets dans les environnements développeurs et les gestionnaires de paquets
* Tester régulièrement la restauration des sauvegardes et leur immuabilité
* Mettre en place un monitoring des fraudes mobiles (NFC) et un contrôle d'intégrité des pages de paiement e-commerce

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Constituer et maintenir un inventaire des actifs exposés à Internet et des frameworks/applications concernés par les CVE activement exploitées
* Prioriser la remédiation des vulnérabilités combinant accessibilité réseau, peu de prérequis et exécution de code
* Renforcer la gouvernance des identifiants développeurs (MFA, jetons à durée courte, secrets scanning) et la sécurité des environnements de développement
* Garantir la résilience des sauvegardes (immuabilité, tests de restauration) et encadrer les outils d'accès à distance légitimes (RMM)

#### Phase 2 — Détection et analyse

* Détecter des séquences comportementales suspectes (exécution, obfuscation, découverte, transfert de payload) plutôt que des événements isolés
* Alerter sur l'usage anormal d'outils légitimes et de plateformes de confiance détournés pour l'accès initial, le vol d'identifiants et le mouvement latéral
* Surveiller l'exploitation des CVE listées dans le rapport et les tentatives d'accès sans authentification sur les services exposés
* Contrôler l'intégrité des scripts de checkout e-commerce (détection Magecart/skimming) et les intégrations tierces de paiement

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes présentant des signes d'exploitation ou d'activité RAT et révoquer les identifiants compromis
* Bloquer les infrastructures C2 et les canaux de transfert de payload identifiés
* Segmenter les environnements développeurs et les systèmes de paiement pour limiter la propagation
* Suspendre les intégrations tierces compromises et purger les code injectés (skimmers) des pages de paiement

#### Phase 4 — Activités post-incident

* Déterminer la vulnérabilité initiale exploitée et vérifier l'absence de réexploitation via d'autres CVE de la liste
* Analyser les playbooks post-exploitation réutilisés par l'attaquant pour enrichir les cas de détection
* Revoir les accès des tiers et des fournisseurs impliqués dans l'intrusion
* Formaliser les enseignements (délais de patch, couverture de détection) et ajuster la politique de gestion d'exposition

#### Phase 5 — Threat Hunting (proactif)

* Chasser proactivement les traces d'exploitation des 215 CVE activement exploitées identifiées au S1 2026, en priorité celles exploitables à distance sans authentification
* Rechercher les usages détournés d'outils d'administration à distance et de plateformes légitimes dans les journaux d'authentification et de processus
* Traquer les compromissions de chaîne d'approvisionnement logicielle (paquets modifiés, intégrations IA, jetons de publication) dans les environnements de développement
* Surveiller les flux mobiles anormaux (fraude NFC, overlays de paiement) sur le parc d'appareils d'entreprise

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195** | Supply Chain Compromise : compromissions de gestionnaires de paquets, d'environnements développeurs et d'outils IA pour propager l'intrusion vers les écosystèmes cloud et logiciels en aval |
| **T1219** | Remote Access Software : prédominance continue des RAT dans l'activité malware du S1 2026 |

---

### Sources

* [https://www.recordedfuture.com/research/h1-2026-malware-vulnerability-trends](https://www.recordedfuture.com/research/h1-2026-malware-vulnerability-trends)


---

<div id="un-operateur-sinophone-utilise-des-agents-ia-framework-secflow-contre-des-systemes-gouvernementaux-et-educatifs-en-asie"></div>

## Un opérateur sinophone utilise des agents IA (framework SecFlow) contre des systèmes gouvernementaux et éducatifs en Asie

### Résumé

Hunt.io publie le 3 septembre 2026 l'analyse d'un framework d'orchestration d'agents IA baptisé SecFlow, utilisé par un opérateur sinophone non attribué pour cibler des systèmes gouvernementaux et éducatifs à travers l'Asie. SecFlow prend en charge des modèles permutables (Claude, Qwen, DeepSeek), s'appuie sur un serveur MCP désigné « GLUTTON » et exécute des playbooks de vulnérabilités adaptés à chaque cible, industrialisant ainsi la reconnaissance et l'exploitation.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller les flux vers les API de modèles de langage, y compris les modèles chinois, et détecter la présence de frameworks d'orchestration d'agents ou de serveurs MCP non répertoriés. Les cadences de scan et d'exploitation automatisées (requêtes régulières, enchaînements mécaniques reconnaissance-exploitation) constituent des signaux détectables. Pour les entités publiques et éducatives, le durcissement des applications exposées et la journalisation centralisée sont des prérequis pour distinguer une automatisation offensive d'un test légitime.

---

### Implications stratégiques

Ce cas démontre que des acteurs à ressources limitées peuvent désormais industrialiser des intrusions grâce à des agents IA orchestrés et à des modèles accessibles, y compris open weights. Le ciblage de secteurs gouvernementaux et éducatifs en Asie suggère un intérêt pour l'espionnage ou l'accès à des données sensibles, tandis que l'usage de modèles multiples complique l'attribution et annonce une banalisation de l'automatisation offensive dans les menaces étatiques et para-étatiques.

---

### Recommandations

* Inventorier et contrôler les accès aux API LLM (clés, quotas, journalisation)
* Détecter et bloquer les serveurs MCP et frameworks d'orchestration non autorisés
* Durcir et exposer a minima les applications publiques des systèmes gouvernementaux et éducatifs
* Corréler les scans automatisés à une éventuelle campagne ciblée sectorielle
* Partager les indicateurs avec les CERT et les entités homologues du secteur public

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les surfaces exposées des systèmes gouvernementaux et éducatifs et prioriser leur durcissement
* Encadrer l'usage des API de modèles de langage (fournisseurs occidentaux et chinois) : clés nominatives, quotas, journalisation
* Documenter les frameworks d'orchestration d'agents IA et les serveurs MCP légitimes utilisés par l'organisation
* Définir des seuils d'alerte sur les cadences de scan et d'exploitation automatisées

#### Phase 2 — Détection et analyse

* Détecter les appels sortants vers des API de modèles LLM non autorisées (notamment Qwen, DeepSeek) depuis le périmètre
* Alerter sur la présence ou l'exécution de frameworks d'orchestration d'agents IA et de serveurs MCP inconnus (type GLUTTON)
* Corréler les scans de vulnérabilités et les tentatives d'exploitation présentant une cadence régulière et automatisée
* Surveiller les accès anormaux aux systèmes gouvernementaux et éducatifs exposés

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les endpoints d'API LLM et les infrastructures utilisées par l'orchestration des agents
* Isoler les systèmes ciblés ayant fait l'objet d'exploitation et révoquer les clés API et identifiants exposés
* Couper les intégrations MCP non légitimes et préserver les artefacts d'orchestration pour analyse

#### Phase 4 — Activités post-incident

* Reconstituer les playbooks de vulnérabilités employés par cible et enrichir les cas de détection correspondants
* Évaluer l'étendue de l'accès obtenu sur les systèmes gouvernementaux/éducatifs compromis
* Partager les indicateurs d'automatisation offensive avec les CERT nationaux et les partenaires sectoriels

#### Phase 5 — Threat Hunting (proactif)

* Chasser les traces d'agents IA : user-agents atypiques, cadences de requêtes mécaniques, enchaînements reconnaissance/exploitation automatisés
* Rechercher les exploitations récentes visant des entités gouvernementales et éducatives en Asie et les schémas d'attaque récurrents par cible
* Identifier toute persistance liée à des serveurs MCP ou frameworks d'orchestration déployés sur les systèmes internes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application : playbooks de vulnérabilités par cible suggérant l'exploitation automatisée d'applications exposées |

---

### Sources

* [https://hunt.io/blog/chinese-operator-secflow-claude-qwen-deepseek-asia](https://hunt.io/blog/chinese-operator-secflow-claude-qwen-deepseek-asia)
* [https://www.reddit.com/r/redteamsec/comments/1w6d6ls/secflow_ai_orchestration_framework_with_swappable/](https://www.reddit.com/r/redteamsec/comments/1w6d6ls/secflow_ai_orchestration_framework_with_swappable/)


---

<div id="ghostworker-implant-furtif-sur-passerelles-unifi-rappelant-via-les-dns-de-google"></div>

## GHOSTWORKER : implant furtif sur passerelles UniFi rappelant via les DNS de Google

### Résumé

Offseq publie le 3 septembre 2026 une analyse décrivant GHOSTWORKER, un implant furtif opérant sur des passerelles UniFi (Ubiquiti). L'implant communique avec son opérateur en passant par l'infrastructure DNS publique de Google, un choix qui lui permet de masquer son trafic de commande et contrôle au sein d'un flux DNS apparemment légitime et difficile à bloquer.

---

### Analyse opérationnelle

La compromission d'une passerelle réseau échappe aux EDR classiques et offre à l'attaquant un point de persistance et d'interception central. Les équipes doivent inventorier leurs équipements UniFi, vérifier l'intégrité des firmwares installés par rapport aux images officielles, et surveiller les requêtes DNS émises par les équipements réseau vers 8.8.8.8 ou dns[.]google, ainsi que tout trafic sortant inattendu. Le blocage du DNS sortant direct au profit de résolveurs internes et la restriction de l'administration à un VLAN dédié limitent l'exploitation de ce type d'implant.

---

### Implications stratégiques

Ce cas illustre la montée des menaces ciblant les appliances réseau, particulièrement répandues dans les PME et les infrastructures distribuées, où elles constituent des pivots persistants invisibles des outils de détection endpoint. Il souligne la nécessité d'étendre les programmes de détection et de gestion d'exposition aux équipements réseau, et interroge sur la confiance accordée aux chaînes de mise à jour des équipements d'infrastructure.

---

### Recommandations

* Inventorier les passerelles UniFi/Ubiquiti et vérifier l'intégrité de leur firmware
* Interdire le DNS sortant direct des équipements réseau vers des résolveurs publics
* Restreindre l'administration réseau à un VLAN de gestion avec MFA et journalisation centralisée
* Surveiller les rappels DNS périodiques vers 8.8.8.8 / dns[.]google depuis les équipements d'infrastructure
* Prévoir une procédure de réinstallation firmware officielle et de rotation des identifiants en cas de compromission

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier toutes les passerelles et équipements UniFi/Ubiquiti en production avec versions de firmware
* Restreindre l'administration des équipements réseau à un VLAN de gestion dédié et imposer un MFA sur les interfaces d'administration
* Centraliser les journaux des équipements réseau (syslog) vers un SIEM et journaliser les requêtes DNS sortantes
* Mettre en place un contrôle d'intégrité du firmware (comparaison aux images officielles Ubiquiti)

#### Phase 2 — Détection et analyse

* Alerter sur les requêtes DNS émises directement par les passerelles vers les résolveurs publics de Google (8.8.8.8, dns[.]google) hors usage standard
* Détecter tout trafic sortant inattendu ou périodique initié depuis les passerelles UniFi
* Comparer les checksums des firmwares installés aux images officielles pour repérer un implant ou un binaire modifié
* Surveiller les modifications de configuration non planifiées sur les équipements réseau

#### Phase 3 — Confinement, éradication et récupération

* Isoler la passerelle compromise du réseau et basculer le routage sur un équipement sain
* Réinstaller un firmware officiel vérifié et révoquer/renouveler l'ensemble des identifiants d'administration
* Bloquer le DNS sortant direct depuis les équipements réseau au profit de résolveurs internes contrôlés
* Préserver l'image mémoire et le firmware suspect pour analyse forensique avant réinstallation

#### Phase 4 — Activités post-incident

* Déterminer le vecteur d'installation de l'implant (mise à jour trojanisée, accès administrateur abusé, chaîne d'approvisionnement)
* Évaluer ce qui a transité par la passerelle compromise (identifiants, trafic intercepté, pivots vers le LAN)
* Revoir la chaîne de distribution et de mise à jour des firmwares et renforcer les contrôles d'intégrité
* Documenter l'incident et partager les indicateurs avec la communauté et le fournisseur

#### Phase 5 — Threat Hunting (proactif)

* Chasser sur l'ensemble du parc réseau les équipements présentant des rappels DNS périodiques vers les résolveurs publics de Google
* Rechercher toute persistance sur les équipements réseau (binaires non officiels, tâches planifiées, clés SSH inconnues)
* Identifier d'éventuelles connexions sortantes chiffrées initiées depuis le VLAN de gestion
* Vérifier les journaux d'administration des passerelles pour des accès ou mises à jour non planifiées

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1071.004** | Application Layer Protocol: DNS : canal de rappel (C2) de l'implant GHOSTWORKER via l'infrastructure DNS publique de Google pour se fondre dans le trafic légitime |

---

### Sources

* [https://offseq.com/en/research/unifi-updater-implant/](https://offseq.com/en/research/unifi-updater-implant/)
* [https://www.reddit.com/r/redteamsec/comments/1w61ym9/ghostworker_a_stealth_unifi_gateway_implant_that/](https://www.reddit.com/r/redteamsec/comments/1w61ym9/ghostworker_a_stealth_unifi_gateway_implant_that/)


---

<div id="nodejs-le-retour-dune-vieille-technique-dexecution-et-de-persistance-detournee"></div>

## Node.js : le retour d'une vieille technique d'exécution et de persistance détournée

### Résumé

La Symantec Threat Hunter Team observe depuis février 2026 un regain d'abus de Node.js par plusieurs acteurs, avec des victimes incluant des ministères, des entreprises technologiques et des hôtels. L'attrait de la technique repose sur le fait que node.exe est un outil de développement légitime et signé : le code malveillant réside dans des scripts interprétés plutôt que dans un binaire, ce qui réduit la probabilité de détection par signatures, et une clé Run dans le registre permet de relancer la charge utile à chaque connexion. Entre mars et juillet 2026, des attaquants ayant compromis une start-up technologique asiatique — dont presque toutes les charges utiles, dont des agents AdaptixC2 et Cobalt Strike Beacon, étaient bloquées — ont téléchargé l'installateur officiel Node.js depuis nodejs[.]org et utilisé le runtime pour exécuter un implant maintenant sa présence pendant des mois et se connectant à des passerelles blockchain Ethereum, vraisemblablement pour récupérer des commandes ou charges utiles cachées dans un smart contract (technique « EtherHiding »). L'accès initial dans cette intrusion a utilisé la technique ClickFix, avec activité PowerShell suspecte, spoofing du domaine d'une société nommée Devmine et « datalyerservice » utilisé comme serveur C2. Les mêmes acteurs ont également compromis une société fintech américaine en déployant un backdoor en Rust nommé C2Looper, lié à des attaques de ransomware. Certaines attaques impliquaient ModeloRAT, attribué au courtier d'accès initiaux Woodgnat (aka KongTuke), publiquement lié à des attaques impliquant plusieurs familles de ransomware dont Qilin, Interlock, Rhysida, Akira, 8Base, Black Basta et Embargo ; un autre backdoor, Backdoor.Mistic, serait également développé par cet acteur.

---

### Analyse opérationnelle

Pour les équipes SOC/IT, l'enjeu principal est la détection d'un interpréteur légitime signé utilisé comme vecteur d'exécution : les détections basées sur les signatures de binaires sont contournées puisque la logique malveillante est dans des scripts JavaScript. Points de contrôle concrets : exécution de node.exe hors des environnements de développement ou depuis des répertoires utilisateurs/temp, clés Run du registre référençant node, téléchargement de l'installateur Node.js depuis nodejs[.]org sur des postes non-développeurs, connexions réseau de node.exe vers des passerelles blockchain Ethereum (indicateur fort d'EtherHiding), activité PowerShell suspecte consécutive à un scénario ClickFix, et communications vers le C2 'datalyerservice' ou des domaines usurpés (Devmine). La surface d'attaque inclut les postes utilisateurs sans besoin de privilèges développeur. Mesures techniques : contrôle applicatif (AppLocker/WDAC) restreignant node.exe, journalisation Sysmon des processus et du registre, blocage des domaines C2, corrélation EDR/SIEM des chaînes ClickFix → PowerShell → node.exe. Les implants à surveiller incluent C2Looper (Rust), ModeloRAT et Backdoor.Mistic.

---

### Implications stratégiques

Cette campagne illustre une tendance structurelle : le détournement d'outils de développement signés (approche LOLBin/LOTL) pour contourner les défenses basées sur la confiance et les signatures, rendant la prévention pure de plus en plus inefficace au profit de la détection comportementale. L'usage d'EtherHiding (C2 via smart contract Ethereum) complique les takedowns et le blocage des infrastructures, car la résilience est assurée par la blockchain elle-même — un signal de professionnalisation croissante des chaînes d'attaque. Le rôle du courtier d'accès initiaux Woodgnat (KongTuke), lié à de nombreuses familles de ransomware (Qilin, Interlock, Rhysida, Akira, 8Base, Black Basta, Embargo), confirme la spécialisation de l'écosystème cybercriminel : une compromission initiale peut déboucher sur des déploiements de ransomware par des affiliés distincts, avec un risque business élevé (chiffrement, exfiltration, interruption d'activité). Le ciblage multi-sectoriel — gouvernement, technologie, hôtellerie, fintech — impose une veille sectorielle et une priorisation des contrôles sur les interpréteurs légitimes présents dans le parc.

---

### Recommandations

* Restreindre et journaliser l'exécution de node.exe hors des environnements de développement via contrôle applicatif
* Surveiller les clés Run et les connexions réseau de node.exe, notamment vers des passerelles blockchain Ethereum
* Détecter et bloquer les téléchargements de l'installateur Node.js sur les postes non-développeurs
* Sensibiliser les utilisateurs à la technique ClickFix et aux fausses fenêtres d'erreur/CAPTCHA
* Bloquer les domaines de C2 identifiés (datalyerservice) et surveiller le spoofing de domaines de prestataires
* Suivre les publications sur Woodgnat/KongTuke, ModeloRAT, C2Looper et Backdoor.Mistic pour enrichir les règles de détection

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les équipes SOC au détournement d'interpréteurs légitimes signés (node.exe) comme technique d'exécution et de persistance
* Déployer Sysmon/EDR avec journalisation des créations de processus, lignes de commande, modifications de clés Run et connexions réseau par processus
* Restreindre l'exécution de node.exe sur les postes non-développeurs via AppLocker/WDAC (politiques de contrôle applicatif)
* Mettre en place la détection des téléchargements d'installateurs depuis nodejs[.]org hors environnements de développement
* Intégrer les règles Sigma couvrant l'exécution JavaScript, la persistance registre et l'activité PowerShell suspecte
* Former les utilisateurs à la technique ClickFix (fausses fenêtres CAPTCHA/erreurs incitant à exécuter des commandes)

#### Phase 2 — Détection et analyse

* Alerter sur toute exécution de node.exe depuis des répertoires utilisateurs/temp ou hors chemins standards de développement
* Détecter les clés Run du registre référençant node.exe ou des scripts .js
* Surveiller les connexions réseau initiées par node.exe vers des passerelles blockchain Ethereum ou des domaines inconnus
* Corréler l'activité PowerShell suspecte avec des indicateurs ClickFix (commandes copiées-collées, encodage inhabituel)
* Détecter le spoofing de domaines (ex : Devmine) et les communications vers le serveur C2 'datalyerservice'
* Identifier les déploiements d'agents post-exploitation (Cobalt Strike Beacon, AdaptixC2) et backdoors Rust (C2Looper), ModeloRAT, Backdoor.Mistic

#### Phase 3 — Confinement, éradication et récupération

* Isoler les machines où node.exe s'exécute de manière suspecte ou communique avec des passerelles blockchain
* Supprimer les clés Run de persistance et les scripts JavaScript malveillants associés
* Bloquer les domaines/IP de C2 identifiés (datalyerservice, passerelles blockchain Ethereum utilisées)
* Empêcher l'exécution de node.exe non autorisé via politique de contrôle applicatif le temps de l'investigation
* Révoquer et renouveler les identifiants des comptes potentiellement compromis
* Bloquer l'accès aux domaines usurpés utilisés pour l'accès initial

#### Phase 4 — Activités post-incident

* Analyser les scripts JavaScript déployés pour identifier le C2, les capacités de l'implant et le lien éventuel avec C2Looper, ModeloRAT ou Backdoor.Mistic
* Vérifier les mouvements latéraux et le déploiement d'outils post-exploitation (Cobalt Strike, AdaptixC2)
* Évaluer le risque de déploiement de ransomware compte tenu des liens de l'acteur avec Qilin, Interlock, Rhysida, Akira, 8Base, Black Basta et Embargo
* Reconstituer la chronologie complète de l'intrusion (accès initial ClickFix, installation Node.js, persistance, C2 blockchain)
* Documenter les leçons apprises et partager les IOC avec les communautés de partage (ISAC, CERT)

#### Phase 5 — Threat Hunting (proactif)

* Chasser les processus node.exe présentant des connexions réseau sortantes anormales ou vers des passerelles blockchain Ethereum (EtherHiding)
* Rechercher les installations récentes de Node.js (installateur officiel) sur des machines n'appartenant pas à des développeurs
* Rechercher les clés Run et tâches de démarrage référençant node ou des scripts JavaScript
* Identifier les artefacts et comportements associés à C2Looper, ModeloRAT et Backdoor.Mistic
* Passer au crible les télémétries PowerShell pour détecter des traces de la technique ClickFix (commandes encodées, exécutions manuelles inhabituelles)
* Rechercher les connexions vers le domaine 'datalyerservice' et les domaines usurpés similaires

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `datalyerservice` | Low |
| DOMAIN | `login[.]in` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1059.007** | JavaScript/JScript : exécution de code malveillant via l'interpréteur légitime node.exe (scripts interprétés plutôt que binaire) |
| **T1547.001** | Registry Run Keys / Startup Folder : persistance via une clé Run relançant node à chaque connexion |
| **T1105** | Ingress Tool Transfer : téléchargement de l'installateur officiel Node.js depuis nodejs[.]org pour déposer un runtime signé |
| **T1071.001** | Web Protocols : communications C2 avec des passerelles blockchain Ethereum (technique EtherHiding) pour récupérer commandes/payloads via smart contract |
| **T1204.002** | User Execution : accès initial via la technique d'ingénierie sociale ClickFix suivie d'activité PowerShell |

---

### Sources

* [https://www.security.com/threat-intelligence/node-js-returns-ransomware](https://www.security.com/threat-intelligence/node-js-returns-ransomware)


---

<div id="sigmahq-mises-a-jour-du-depot-sigma-renommage-des-regles-appxdeployment-server-et-ajout-de-tests-de-regression"></div>

## SigmaHQ : mises à jour du dépôt Sigma — renommage des règles appxdeployment-server et ajout de tests de régression

### Résumé

Le 3 septembre 2026, le dépôt SigmaHQ/sigma a intégré quatre pull requests : PR #6268 (renommage des règles relatives à AppXDeployment-Server, contribution de @SmongsDev), PR #6213 et PR #6221 (ajout de tests de régression pour plusieurs règles, contributions de @frack113) et PR #6272 (optimisation du temps d'exécution des tests de régression, contribution de @swachchhanda000). Aucun IOC, aucune vulnérabilité ni campagne de menace n'est associé à ces commits.

---

### Analyse opérationnelle

Les équipes SOC exploitant des règles Sigma doivent synchroniser leurs dépôts locaux : le renommage des règles appxdeployment-server peut rompre les références internes (dashboards, playbooks SOAR, mappings MITRE) pointant vers les anciens titres. Les tests de régression ajoutés réduisent le risque de faux positifs et de faux négatifs, et l'optimisation du runtime des tests accélère la validation des contributions. Il est recommandé de vérifier les diffs des règles concernées avant tout déploiement en production.

---

### Implications stratégiques

Cette maintenance continue illustre la dépendance des SOC aux contenus de détection open source communautaires. Sans processus formalisé de veille et de validation des mises à jour de règles (gestion du contenu de détection), les organisations s'exposent à des ruptures silencieuses de couverture de détection et à une dérive de la qualité des alertes.

---

### Recommandations

* Synchroniser le dépôt Sigma et auditer les règles renommées (appxdeployment-server) pour mettre à jour les références internes
* Intégrer les tests de régression Sigma dans le pipeline CI/CD du contenu de détection
* Mettre en place une surveillance des changements du dépôt SigmaHQ (webhooks, releases) pour anticiper les impacts sur les cas d'usage de détection

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire des règles Sigma déployées en production et de leurs cas d'usage associés
* Mettre en place un pipeline de validation (tests de régression) avant tout déploiement de règles en production
* Documenter les références internes (dashboards, playbooks SOAR, mappings MITRE) pointant vers les titres/identifiants des règles

#### Phase 2 — Détection et analyse

* Surveiller les commits et PR du dépôt SigmaHQ (webhooks, flux) pour identifier renommages, suppressions et modifications de règles
* Après synchronisation, vérifier qu'aucune règle critique n'a été supprimée ou renommée sans mise à jour des références internes

#### Phase 3 — Confinement, éradication et récupération

* En cas de rupture de détection causée par un renommage, réactiver temporairement l'ancienne version de la règle depuis l'historique git
* Geler le déploiement automatique des règles en production le temps de la validation des changements

#### Phase 4 — Activités post-incident

* Réaliser un bilan de couverture de détection après mise à jour du référentiel (règles impactées, écarts comblés)
* Documenter le retour d'expérience et mettre à jour la procédure de gestion du contenu de détection

#### Phase 5 — Threat Hunting (proactif)

* Utiliser les règles renommées relatives à AppXDeployment-Server pour rechercher des abus de déploiement de packages AppX malveillants sur les endpoints Windows
* Rejouer les tests de régression sur des jeux de données historiques pour valider la stabilité et la précision des règles mises à jour

---

### Sources

* [https://github.com/SigmaHQ/sigma/commit/2d97ff865ed37b0558eb564f8a69691535de2fd2](https://github.com/SigmaHQ/sigma/commit/2d97ff865ed37b0558eb564f8a69691535de2fd2)
* [https://github.com/SigmaHQ/sigma/commit/583537e26d32f8be724d1a3688f1b11c7f242c38](https://github.com/SigmaHQ/sigma/commit/583537e26d32f8be724d1a3688f1b11c7f242c38)
* [https://github.com/SigmaHQ/sigma/commit/642891fe0049360a4c03693b3f735c1cca300047](https://github.com/SigmaHQ/sigma/commit/642891fe0049360a4c03693b3f735c1cca300047)
* [https://github.com/SigmaHQ/sigma/commit/4e2e0a8acc9f53553c01f0dda2a8023fd90845fb](https://github.com/SigmaHQ/sigma/commit/4e2e0a8acc9f53553c01f0dda2a8023fd90845fb)


---

<div id="space-bears-deux-nouvelles-victimes-revendiquees-sur-son-site-de-fuite-sgla-et-studio-oculistico-ciraci"></div>

## Space Bears : deux nouvelles victimes revendiquées sur son site de fuite (SGLA et Studio Oculistico Ciraci)

### Résumé

Le 3 septembre 2026, le groupe ransomware Space Bears a publié deux nouvelles victimes sur son site de fuite : « Schwartz, Giannini, Lantsberger & Adamson (SGLA) » et « Studio Oculistico Ciraci », un cabinet ophtalmologique. Ces publications sont relayées par les services de monitoring RansomLook et cti.fyi. Aucun détail technique (montant de rançon, preuves d'exfiltration, IOC) n'est disponible dans les sources.

---

### Analyse opérationnelle

Intégrer le groupe Space Bears et ses infrastructures de fuite à la veille CTI. Pour les organisations du secteur santé et les cabinets professionnels, vérifier l'absence d'indicateurs de compromission liés à ce groupe. La publication sur un site de fuite s'inscrit typiquement dans une logique de double extorsion (chiffrement et menace de publication de données) : toute réclamation doit être traitée comme un signal potentiel de compromission d'un partenaire, client ou sous-traitant. Mettre en place un monitoring continu des sites de fuite pour détecter d'éventuelles fuites concernant l'organisation ou ses tiers.

---

### Implications stratégiques

La ciblade d'un cabinet médical et d'une structure au nom évocateur d'un cabinet juridique confirme la tendance des groupes ransomware à viser des secteurs détenant des données sensibles et à faible tolérance à l'interruption (santé, services professionnels), où la pression à payer est élevée. Le monitoring des sites de fuite devient un élément clé de la gestion du risque tiers, de la conformité réglementaire (notification des violations de données) et de la protection de la réputation.

---

### Recommandations

* Intégrer le groupe Space Bears et son site de fuite dans la veille CTI et le monitoring des leaks
* Sensibiliser les métiers sensibles (santé, juridique) au risque ransomware et à la double extorsion
* Vérifier les sauvegardes hors ligne et les plans de continuité d'activité pour les systèmes critiques
* Contrôler l'exposition externe (VPN, RDP, accès distants) et appliquer l'authentification multifacteur
* Préparer une procédure de notification et de gestion de crise en cas de fuite de données propre ou de tiers

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir des sauvegardes immuables/hors ligne testées régulièrement (règle 3-2-1)
* Segmenter le réseau et restreindre les mouvements latéraux entre postes de travail, serveurs et systèmes critiques
* Déployer l'EDR sur l'ensemble du parc et centraliser les journaux (authentification, exécution de processus, accès distants)
* Établir un plan de réponse ransomware avec contacts (direction, juridique, assurance, CERT/ANSSI) et procédures de décision (notification, continuité)

#### Phase 2 — Détection et analyse

* Alerter sur les comportements typiques de chiffrement : écritures massives, suppression des shadow copies (vssadmin delete shadows), arrêt des services de sauvegarde
* Surveiller les indicateurs d'exfiltration de données (double extorsion) : outils type rclone/curl vers destinations inhabituelles, transferts volumineux anormaux
* Corréler les accès distants anormaux (VPN, RDP) et l'usage d'outils de reconnaissance interne
* Surveiller les sites de fuite des groupes ransomware, dont Space Bears, pour détecter la citation de l'organisation ou de ses partenaires et sous-traitants

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes compromis du réseau et désactiver les comptes compromis
* Révoquer les sessions/jetons actifs et réinitialiser les identifiants privilégiés
* Bloquer les flux d'exfiltration et de C2 identifiés, et préserver les preuves (images mémoire/disque, journaux) avant toute remédiation

#### Phase 4 — Activités post-incident

* Caractériser l'étendue : vecteur initial, comptes abusés, systèmes chiffrés, données exfiltrées (pour évaluer les obligations de notification RGPD)
* Reconstruire les systèmes depuis des sauvegardes saines après identification et correction du vecteur initial
* Renforcer les contrôles défaillants (MFA, gestion des correctifs, segmentation) et documenter le retour d'expérience
* Coordonner avec les autorités (ANSSI/CERT, forces de l'ordre) et le juridique pour les obligations réglementaires et contractuelles

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'outils d'exfiltration (rclone, Mega, FileZilla) et de transferts de données volumineux anormaux dans les journaux proxy/DNS
* Chasser les techniques d'élévation de privilèges et de reconnaissance Active Directory (énumération de comptes et permissions) dans les télémétries
* Rechercher des artefacts de chiffrement (extensions de fichiers inhabituelles, notes de rançon, processus de chiffrement massif)
* Vérifier la présence d'IOCs publiés par la communauté pour le groupe Space Bears dans les télémétries historiques (EDR, proxy, DNS)

---

### Sources

* [https://www.ransomlook.io//group/space%20bears](https://www.ransomlook.io//group/space%20bears)
* [https://cti.fyi/groups/spacebears.html](https://cti.fyi/groups/spacebears.html)


---

<div id="outils-de-pentest-autonomes-un-classement-criterie-relance-le-debat-sur-la-supervision-humaine-des-exploits-automatiques"></div>

## Outils de pentest autonomes : un classement critérié relance le débat sur la supervision humaine des exploits automatiques

### Résumé

Un article de TNW publie un classement des outils de pentest autonomes fondé sur des critères de preuve d'exploit. Il souligne que le terme « autonome » recouvre un large spectre, de la reconnaissance assistée par scripts aux chaînes agentiques complètes, et que la vraie question est la supervision humaine restant dans la boucle lorsque les exploits se déclenchent automatiquement. Un billet complémentaire sur Mastodon illustre, sous forme d'aphorisme, la progression rapide de ces outils et le risque qu'une machine découvre une faille sans avertir l'opérateur.

---

### Analyse opérationnelle

Pour les équipes offensives et défensives, l'enjeu est de qualifier le degré d'autonomie réel de chaque outil (recon scriptée versus chaîne agentique exploitant seule) et d'imposer des garde-fous : périmètre scellé, journalisation intégrale, validation humaine avant tout exploit à impact. Les équipes bleues doivent anticiper la détection de ces automates (cadences de scan, empreintes d'outils) et cadrer contractuellement les fenêtres de test pour éviter les faux positifs massifs et les dégradations non maîtrisées.

---

### Implications stratégiques

La démocratisation d'outils capables de prouver l'exploitabilité automatiquement réduit le coût d'entrée des tests d'intrusion, mais dilue la responsabilité : qui répond d'un exploit déclenché automatiquement ? Les organisations doivent arbitrer entre gain d'efficience et maîtrise du risque, et s'attendre à voir ces capacités aussi adoptées par des acteurs malveillants, compressant le délai entre découverte et exploitation d'une vulnérabilité.

---

### Recommandations

* Exiger une validation humaine (human-in-the-loop) avant tout exploit automatique à impact
* Restreindre l'exécution des agents de pentest à des environnements isolés et journalisés
* Documenter le niveau d'autonomie de chaque outil retenu et ses critères de preuve d'exploit
* Intégrer les empreintes de ces outils dans les règles de corrélation SOC pour distinguer tests légitimes et attaques

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir une politique d'encadrement des outils de pentest autonomes (périmètre, autorisations, exigence de preuves d'exploit)
* Formaliser un cadre human-in-the-loop : validation humaine obligatoire avant tout exploit à impact (déni de service, modification de données)
* Isoler les environnements de test (labs dédiés, snapshots, réseaux fictifs) pour l'exécution d'agents d'exploitation automatiques
* Journaliser toutes les actions des outils autonomes (requêtes, payloads, exploits déclenchés) pour audit et rejeu

#### Phase 2 — Détection et analyse

* Surveiller les scans et exploits automatisés anormaux : cadence régulière, empreintes d'outils connus, enchaînements recon-vers-exploit sans intervention humaine
* Corréler les alertes IDS/WAF avec les fenêtres de tests autorisés pour distinguer pentest légitime et attaque réelle
* Alerter sur tout exploit déclenché hors du créneau ou du périmètre contractualisé

#### Phase 3 — Confinement, éradication et récupération

* Couper l'accès réseau et les credentials de l'outil autonome dès qu'un exploit non autorisé se déclenche
* Restaurer les systèmes impactés depuis des snapshots pré-tests
* Révoquer les jetons et comptes utilisés par l'agent déréglé ou compromis

#### Phase 4 — Activités post-incident

* Analyser les journaux d'exécution de l'agent pour identifier la chaîne d'exploit et les failles exploitées
* Réévaluer la liste des outils autorisés et leurs critères de preuve d'exploit
* Documenter les enseignements dans le programme de tests d'intrusion (scope, garde-fous)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'usage d'outils de pentest autonomes par des acteurs malveillants (empreintes de scanners, payloads génériques)
* Chasser les exploitations en chaîne rapides (recon-vers-exploit en quelques minutes) dans les logs proxy et EDR
* Vérifier l'exposition des actifs face aux classes de vulnérabilités couvertes par ces outils

---

### Sources

* [https://thenextweb.com/news/best-autonomous-pentesting-tools-proof-exploit-2026](https://thenextweb.com/news/best-autonomous-pentesting-tools-proof-exploit-2026)
* [https://mastobot.ping.moi/@Bobe_bot/117209353916821671](https://mastobot.ping.moi/@Bobe_bot/117209353916821671)


---

<div id="italie-de-fausses-notifications-de-remboursement-tari-servent-dappat-a-de-nouvelles-campagnes-de-phishing-contre-pagopa"></div>

## Italie : de fausses notifications de remboursement TARI servent d'appât à de nouvelles campagnes de phishing contre PagoPA

### Résumé

Le CERT-AGID signale de nouvelles campagnes de hameçonnage exploitant le thème d'un faux remboursement de la taxe TARI (taxe sur les déchets) pour cibler les utilisateurs de PagoPA, la plateforme italienne de paiement des services publics. La publication du CERT ne fournit pas d'indicateurs techniques détaillés dans le flux analysé.

---

### Analyse opérationnelle

Les équipes doivent déployer des règles de détection sur les mots-clés « TARI », « rimborso » et « PagoPA » dans les courriels et bloquer les domaines imitant les portails de paiement publics italiens. En cas de soumission de credentials, la réponse combine réinitialisation immédiate, révocation des sessions et surveillance des transactions sur les comptes concernés. La sensibilisation ciblée des usagers et des agents publics au scénario « remboursement » est un levier immédiat de réduction du risque.

---

### Implications stratégiques

L'usurpation de thèmes fiscaux et de plateformes publiques de paiement touche un très large bassin de victimes potentielles en Italie et fragilise la confiance dans les services numériques publics. Ces campagnes, récurrentes et adaptées à l'actualité administrative locale, imposent aux collectivités et opérateurs publics de renforcer l'authentification forte et les dispositifs de signalement, sous peine de pertes financières directes et d'atteinte réputationnelle.

---

### Recommandations

* Bloquer et surveiller les domaines imitant PagoPA et les thèmes de remboursement TARI
* Imposer la MFA sur les portails de paiement et détecter les soumissions de credentials hors domaines officiels
* Diffuser une alerte de sensibilisation au scénario du faux remboursement TARI
* Signaler les incidents à CERT-AGID et partager les indicateurs avec les partenaires

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les usagers des services publics italiens et les organisations partenaires de PagoPA au scénario du faux remboursement TARI
* Déployer des passerelles mail avec anti-phishing et analyse des URL (rewriting, sandboxing de liens)
* Prévoir une procédure de signalement rapide vers CERT-AGID et l'équipe de réponse à incident
* Durcir l'authentification sur les portails de paiement (MFA, détection de sessions anormales)

#### Phase 2 — Détection et analyse

* Surveiller les messages mentionnant « rimborso TARI », « PagoPA » ou des remboursements fiscaux avec liens externes ou pièces jointes
* Détecter les soumissions de credentials sur des domaines non officiels imitant PagoPA (logs proxy/DNS, alertes MFA)
* Corréler les connexions inhabituelles sur les portails de paiement avec des clics sur des liens de hameçonnage

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les domaines et URL de hameçonnage identifiés au niveau proxy/DNS/passerelle mail
* Réinitialiser immédiatement les credentials des comptes ayant soumis leurs identifiants et révoquer les sessions actives
* Purger les messages frauduleux des boîtes à l'échelle du parc

#### Phase 4 — Activités post-incident

* Évaluer les accès frauduleux obtenus (transactions, données personnelles) et engager les notifications requises
* Analyser l'infrastructure de hameçonnage (enregistrements de domaines, certificats) pour enrichir les blocages
* Partager les indicateurs avec CERT-AGID et les ISAC sectoriels

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans les passerelles mail et les logs web toute référence aux thèmes TARI/PagoPA et aux domaines typosquats
* Rechercher les comptes ayant modifié leurs coordonnées de paiement ou effectué des paiements atypiques après réception de ces messages
* Surveiller l'apparition de nouveaux domaines imitant PagoPA (certificats récents, mots-clés « pago », « rimborso », « tari »)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing : campagnes exploitant un faux remboursement de la taxe TARI pour cibler les utilisateurs de la plateforme de paiement publique PagoPA |

---

### Sources

* [https://cert-agid.gov.it/news/falso-rimborso-tari-sfruttato-nelle-nuove-campagne-di-phishing-ai-danni-di-pagopa/](https://cert-agid.gov.it/news/falso-rimborso-tari-sfruttato-nelle-nuove-campagne-di-phishing-ai-danni-di-pagopa/)


---

<div id="compromission-de-linfrastructure-du-registre-de-coder-pour-pousser-des-modules-malveillants"></div>

## Compromission de l'infrastructure du registre de Coder pour pousser des modules malveillants

### Résumé

Selon un rapport public relayé par BleepingComputer et agrégé dans un pulse Open Threat Exchange (auteur CyberHunter_NL, créé le 2026-09-03), l'infrastructure du registre de Coder a été compromise afin de diffuser des modules malveillants. Des indicateurs ont été extraits du reporting public ; l'auteur du pulse précise que ces données sont non vérifiées et préliminaires, et appelle à une validation complémentaire. Le hashtag RCE associé suggère un potentiel d'exécution de code, sans détail confirmé dans le flux.

---

### Analyse opérationnelle

Les équipes doivent vérifier sans délai si des modules provenant du registre Coder ont été téléchargés ou déployés pendant la fenêtre suspecte, en comparant les hachages aux indicateurs publiés. Les pipelines CI/CD et environnements de développement utilisant Coder constituent la surface prioritaire : gel des déploiements, contrôle d'intégrité des artefacts, isolation des hôtes exécutant des modules suspects et analyse des connexions sortantes. Toute exécution confirmée impose une réponse de type compromission de chaîne d'approvisionnement (reconstruction depuis sources de confiance, rotation des secrets exposés aux environnements de build).

---

### Implications stratégiques

Cette compromission illustre la vulnérabilité persistante des registres de modules et de la chaîne d'approvisionnement logicielle : un point de distribution unique permet d'atteindre simultanément de nombreuses organisations. Pour les directions, l'enjeu est d'imposer la vérification d'intégrité (signatures, hachages, provenance) des dépendances et de prévoir des plans de réponse spécifiques aux compromissions de fournisseurs, avec visibilité contractuelle sur les incidents chez les prestataires de registres.

---

### Recommandations

* Vérifier l'intégrité (hachages/signatures) de tous les modules Coder téléchargés récemment
* Geler les pipelines consommant le registre compromis jusqu'à confirmation de l'assainissement
* Surveiller les comportements post-installation des modules (réseau, exécution de commandes)
* Suivre le pulse OTX et les communications de l'éditeur pour les indicateurs validés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les usages de Coder et de ses registres/modules en interne (versions, sources, signatures)
* Mettre en place la vérification d'intégrité (hachages, signatures) des modules téléchargés depuis des registres tiers
* Définir un plan de réponse type supply chain : gel des déploiements, retrait des artefacts, reconstruction depuis sources de confiance

#### Phase 2 — Détection et analyse

* Comparer les hachages des modules Coder installés localement avec les listes d'indicateurs publiées (pulse OTX, éditeur)
* Surveiller les comportements post-installation anormaux des modules (connexions sortantes inattendues, exécution de commandes, RCE)
* Alerter sur tout téléchargement récent de modules depuis le registre compromis pendant la fenêtre d'exposition

#### Phase 3 — Confinement, éradication et récupération

* Suspendre les pipelines CI/CD tirant des modules du registre compromis
* Isoler les hôtes exécutant des modules suspects et couper leurs communications sortantes
* Retirer ou mettre en quarantaine les modules malveillants identifiés des registres internes et des postes de développement

#### Phase 4 — Activités post-incident

* Reconstruire les environnements touchés depuis des sources vérifiées et re-signer les artefacts
* Analyser les journaux pour déterminer si les modules malveillants ont été exécutés et quelles actions ils ont menées (exfiltration, persistance)
* Documenter la fenêtre de compromission et renforcer les contrôles d'intégrité de la chaîne d'approvisionnement

#### Phase 5 — Threat Hunting (proactif)

* Chasser les hachages et noms de modules malveillants dans les registres internes, caches proxy et artefacts CI
* Rechercher des processus enfants anormaux issus des environnements Coder (shells inversés, téléchargements d'outils)
* Vérifier les connexions réseau des environnements de développement vers des infrastructures inconnues pendant la période suspecte

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromise Software Supply Chain : compromission de l'infrastructure de registre pour diffuser des modules malveillants |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/](https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/)
* [https://otx.alienvault.com/pulse/6a99dec79581ad186b15ab7e](https://otx.alienvault.com/pulse/6a99dec79581ad186b15ab7e)


---

<div id="plex-presse-ses-utilisateurs-de-corriger-des-vulnerabilites-de-plex-media-server-encore-sans-identifiants-cve"></div>

## Plex presse ses utilisateurs de corriger des vulnérabilités de Plex Media Server, encore sans identifiants CVE

### Résumé

Plex a averti ses utilisateurs de corriger sans délai des failles de sécurité affectant Plex Media Server en version 1.43.2 et antérieures. Ces vulnérabilités ne disposent pas encore d'identifiants CVE et l'éditeur n'a pas fourni de détails techniques. Des courriels ont été envoyés aux utilisateurs des versions concernées pour leur demander de mettre à jour. Les correctifs sont livrés dans Plex Media Server 1.43.3 et Plex Desktop 1.115.0.

---

### Analyse opérationnelle

Action immédiate : inventorier les instances Plex et forcer la mise à jour vers Plex Media Server 1.43.3 et Plex Desktop 1.115.0. En l'absence de CVE et de détails techniques, la détection repose sur la gestion de versions (repérage des instances 1.43.2 et antérieures) et la surveillance des journaux d'accès aux serveurs Plex exposés. Réduire l'exposition internet des instances non à jour (accès VPN, règles de pare-feu) limite le risque pendant la fenêtre de correction.

---

### Implications stratégiques

Les logiciels grand public auto-hébergés comme Plex sont fréquemment exposés sur internet et constituent des cibles de prédilection pour l'exploitation de masse dès publication de détails. L'absence de CVE complique le suivi et la priorisation pour les équipes qui s'appuient sur les bases de vulnérabilités : il faut intégrer les avis éditeurs sans identifiant dans le processus de gestion des correctifs, sous peine de laisser des surfaces exposées non inventoriées.

---

### Recommandations

* Mettre à jour vers Plex Media Server 1.43.3 et Plex Desktop 1.115.0 sans attendre l'attribution de CVE
* Limiter l'exposition internet des instances Plex (VPN, règles de pare-feu)
* Surveiller les journaux Plex pour des accès anormaux avant et après correctif
* Suivre les publications de l'éditeur et les relais spécialisés pour les détails techniques et CVE à venir

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les instances Plex Media Server et Plex Desktop du parc avec leurs versions exactes
* Définir une politique de mise à jour rapide pour les logiciels exposés (accès distant, relais internet)
* Prévoir des sauvegardes de configuration avant mise à jour

#### Phase 2 — Détection et analyse

* Identifier toutes les instances en version Plex Media Server 1.43.2 ou antérieure et Plex Desktop antérieure à 1.115.0
* Surveiller les journaux Plex pour des accès anormaux (authentifications inusuelles, requêtes suspectes sur les endpoints d'administration)
* Suivre l'attribution future de CVE et la publication de preuves de concept pour évaluer le risque d'exploitation active

#### Phase 3 — Confinement, éradication et récupération

* Appliquer immédiatement Plex Media Server 1.43.3 et Plex Desktop 1.115.0
* Restreindre temporairement l'exposition internet des serveurs Plex (accès via VPN uniquement) en attendant la mise à jour
* Révoquer les sessions et tokens actifs après la mise à jour en cas de suspicion de compromission

#### Phase 4 — Activités post-incident

* Vérifier l'intégrité des bibliothèques et des comptes (modifications non autorisées, partages ajoutés)
* Analyser les journaux antérieurs à la mise à jour pour détecter toute exploitation
* Documenter la fenêtre d'exposition et les mesures correctives

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs des requêtes d'exploitation typiques sur les endpoints Plex avant correctif
* Chasser les connexions entrantes inhabituelles vers les ports Plex exposés
* Vérifier la création de partages de bibliothèque ou de comptes inconnus

---

### Sources

* [https://www.bleepingcomputer.com/news/security/plex-warns-users-to-patch-security-vulnerabilities-immediately/](https://www.bleepingcomputer.com/news/security/plex-warns-users-to-patch-security-vulnerabilities-immediately/)


---

<div id="ephemora-cell-un-runtime-wasm-a-capacites-pour-executer-en-sandbox-le-code-genere-par-les-agents-ia"></div>

## Ephemora Cell : un runtime WASM à capacités pour exécuter en sandbox le code généré par les agents IA

### Résumé

Le projet open source Ephemora Cell (GitHub) propose une couche d'exécution WASM à base de capacités pour le code non fiable, notamment généré par des agents IA. Chaque exécution applique des limites explicites : mémoire 128 Mo, budget CPU (fuel 1 000 000), timeout de 30 s, sorties plafonnées à 10 Ko, réseau désactivé (aucune API socket WASI), système de fichiers hôte refusé par défaut avec 14 répertoires dangereux bloqués, exec/fork indisponibles et threads désactivés. Le projet revendique une exécution à chaud sub-milliseconde (0,16 ms invité / 0,46 ms bout en bout) et la production d'enregistrements d'exécution signés. Une vérification annoncée le 2026-09-02 indique que 8 primitives d'attaque (shell, fork, socket, système de fichiers hôte, échappement par symlink, etc.) réussissent dans un conteneur python:3.12-slim standard (0/8 bloquées) mais sont toutes bloquées par Ephemora Cell (8/8), avec scripts de reproduction fournis.

---

### Analyse opérationnelle

Pour les équipes exploitant des agents IA, MCP ou interpréteurs de code, l'outil offre un contrôle concret de la surface d'attaque : exécution systématique en sandbox avec quotas appliqués (et non seulement documentés), réseau coupé par défaut, système de fichiers hôte refusé et enregistrements signés vérifiables. Les équipes peuvent intégrer les scripts de vérification fournis (verify_8_vectors.py, demo_attack_probe.py) à leurs tests d'acceptation sécurité et traiter les dépassements de quotas comme des signaux de code hostile. Points de vigilance : maturité du projet, double ABI WASI et memory64 en opt-in à activer prudemment, médiateur egress fourni à titre de référence à valider avant production.

---

### Implications stratégiques

L'exécution de code généré par IA devient un risque opérationnel majeur à mesure que les agents écrivent et exécutent du code : sans isolation appliquée, un conteneur standard laisse passer l'ensemble des primitives d'attaque testées. Les organisations déployant des agents doivent inscrire le sandboxing par défaut dans leur politique de sécurité IA, faute de quoi credentials, réseau et système de fichiers hôtes restent exposés. La disponibilité d'outils open source à faible latence réduit l'argument du coût du sandboxing dans les arbitrages build versus buy.

---

### Recommandations

* Imposer l'exécution en sandbox (WASM/microVM) de tout code généré par IA avant intégration
* Désactiver le réseau et l'accès au système de fichiers hôte par défaut pour les workloads non fiables
* Vérifier les enregistrements d'exécution signés et alerter sur les dépassements de quotas
* Reproduire les 8 vecteurs d'attaque du projet dans un environnement de test pour valider le poste de défense

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les flux de code généré par IA/agents exécutés dans l'organisation (MCP, plugins, interpréteurs)
* Définir une politique d'exécution de code non fiable : sandbox obligatoire, quotas de ressources, réseau désactivé par défaut
* Évaluer les runtimes d'isolation (WASM, microVM) et leurs limites documentées

#### Phase 2 — Détection et analyse

* Surveiller les tentatives d'évasion du sandbox : accès aux répertoires sensibles (/dev, /proc, /sys), appels socket, fork/exec
* Alerter sur les dépassements de quotas (CPU, mémoire, temps, sorties) qui peuvent signaler un code hostile ou déréglé
* Journaliser et vérifier les enregistrements d'exécution signés pour détecter toute altération

#### Phase 3 — Confinement, éradication et récupération

* Couper l'exécution des workloads non fiables dépassant leurs budgets ou tentant un accès hors capacités accordées
* Isoler l'hôte exécutant un module ayant tenté une évasion et analyser le module
* Révoquer les capacités et credentials accessibles à l'agent à l'origine du code

#### Phase 4 — Activités post-incident

* Analyser le module wasm incriminé (imports WASI, comportement) et enrichir les règles de blocage
* Réviser la configuration des limites (mémoire, fuel, I/O) à la lumière de l'incident
* Documenter l'incident dans le référentiel des risques liés aux agents IA

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les exécutions où le code généré a tenté des primitives d'attaque (shell, fork, socket, échappement par symlink, accès au système de fichiers hôte)
* Comparer les enregistrements d'exécution signés aux journaux hôtes pour repérer des exécutions non tracées
* Auditer les intégrations MCP/plugins pour identifier celles exécutant du code sans isolation

---

### Sources

* [https://github.com/MichaelS1011/ephemora-cell](https://github.com/MichaelS1011/ephemora-cell)


---

<div id="deux-nephrology-associates-victimes-de-cyberattaques-une-seule-a-divulgue-lincident"></div>

## Deux « Nephrology Associates » victimes de cyberattaques : une seule a divulgué l'incident

### Résumé

DataBreaches rapporte que deux organisations distinctes portant le nom de « Nephrology Associates » ont été victimes de cyberattaques, mais qu'une seule d'entre elles a publiquement divulgué l'incident. Le contenu détaillé de l'article n'était pas accessible au moment de la collecte (page protégée) ; les informations factuelles disponibles se limitent au titre.

---

### Analyse opérationnelle

Pour les équipes en charge des risques tiers et de la veille : distinguer clairement les deux entités homonymes lors du monitoring des fuites et des évaluations fournisseurs afin d'éviter toute confusion d'attribution. Vérifier si l'une des entités figure dans la chaîne de sous-traitance (cabinets de néphrologie, partenaires de santé) et surveiller les notifications officielles (régulateurs santé, autorités étatiques) pour préciser la nature et l'étendue de l'incident.

---

### Implications stratégiques

La divulgation asymétrique entre deux entités au nom identique illustre les enjeux de transparence dans le secteur de la santé : obligations de notification envers les patients et les régulateurs, risque réputationnel et juridique en cas de non-divulgation, et difficulté pour les tiers d'évaluer le risque lorsque l'information publique est partielle.

---

### Recommandations

* Vérifier la présence des deux entités dans l'écosystème fournisseurs/partenaires de santé
* Surveiller les notifications réglementaires et communiqués officiels pour confirmer l'étendue de l'incident
* En cas de relation commerciale, exiger des informations détaillées sur l'incident (nature, données affectées, mesures correctives)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des actifs et des données de santé (PHI) et de leurs flux
* Tester régulièrement le plan de réponse à incident et les sauvegardes hors ligne (règle 3-2-1)
* Préparer des modèles de notification (patients, régulateurs, assureurs cyber) conformes aux obligations de la juridiction applicable
* Segmenter le réseau clinique/administratif et restreindre l'accès aux dossiers médicaux (MFA, PAM)

#### Phase 2 — Détection et analyse

* Surveiller les alertes EDR/XDR sur les postes et serveurs hébergeant des données de santé
* Corréler les connexions anormales (comptes privilégiés, accès hors heures) sur les systèmes d'information de santé
* Surveiller les fuites de données (clear web, dark web) mentionnant le nom de l'organisation
* Détecter les tentatives d'exfiltration (flux sortants volumineux, DNS anormal)

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis du réseau en préservant les preuves (mémoire, journaux)
* Désactiver les comptes compromis et révoquer sessions et tokens
* Bloquer les IOC identifiés (IP, domaines) au pare-feu et au proxy
* Basculer sur les procédures dégradées pour maintenir la continuité des soins

#### Phase 4 — Activités post-incident

* Mener l'analyse forensique pour déterminer la portée exacte et les données affectées
* Notifier patients et régulateurs dans les délais légaux et documenter la décision de divulgation
* Renforcer les contrôles identifiés comme défaillants (correctifs, MFA, segmentation)
* Réaliser un retour d'expérience et mettre à jour le plan de réponse

#### Phase 5 — Threat Hunting (proactif)

* Chasser les artefacts de persistance sur les serveurs d'application et les postes administratifs
* Rechercher des accès anormaux aux bases de données patients (requêtes massives, exports)
* Vérifier la présence d'outils de tunneling ou d'exfiltration (RDP inversé, stockage cloud)
* Comparer les journaux des entités homonymes si un lien de supply chain est suspecté

---

### Sources

* [https://databreaches.net/2026/09/03/two-nephrology-associates-suffered-cyberattacks-only-one-of-them-has-disclosed-it/](https://databreaches.net/2026/09/03/two-nephrology-associates-suffered-cyberattacks-only-one-of-them-has-disclosed-it/)


---

<div id="ransomware-agentique-une-entreprise-neutralisee-en-dix-heures-lia-laisse-un-audit-de-80-pages"></div>

## Ransomware « agentique » : une entreprise neutralisée en dix heures, l'IA laisse un audit de 80 pages

### Résumé

DataBreaches rapporte le cas d'une entreprise mise hors service en dix heures par un ransomware « agentique » (opéré par une IA autonome) ; selon le titre, l'IA aurait laissé derrière elle un audit de 80 pages documentant ses actions. Le contenu détaillé de l'article n'était pas accessible au moment de la collecte (page protégée) ; les informations factuelles disponibles se limitent au titre.

---

### Analyse opérationnelle

Un délai d'exécution de dix heures implique que les fenêtres de détection doivent être inférieures à quelques heures : corrélation EDR/XDR en temps réel, détection comportementale (mouvement latéral rapide, élévation de privilèges en chaîne, chiffrement massif) et tests réguliers de restauration. L'existence d'un « audit » généré par l'IA suggère des opérations automatisées de bout en bout, réduisant l'efficacité des approches fondées sur des indicateurs statiques au profit de la détection comportementale et des anomalies de rythme.

---

### Implications stratégiques

L'émergence de ransomwares agentiques marque une escalade : réduction du temps d'intervention humain, passage à l'échelle des campagnes et pression accrue sur les budgets de détection/réponse et la cyber-résilience (sauvegardes immuables, plans de continuité). Les directions doivent réévaluer les hypothèses de dwell time dans leurs scénarios de crise et leurs couvertures d'assurance cyber.

---

### Recommandations

* Réduire les délais de détection : corrélation temps réel EDR/SIEM et règles comportementales multi-étapes
* Tester la restauration depuis des sauvegardes immuables avec un objectif de reprise de quelques heures
* Intégrer les scénarios de ransomware automatisé (dwell time < 24 h) dans les exercices de crise
* Durcir le mouvement latéral : MFA, segmentation, surveillance des comptes de service

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sauvegardes immuables/hors ligne testées régulièrement (3-2-1-1-0)
* Durcissement EDR en mode blocage et protection anti-ransomware sur les partages de fichiers
* Segmentation réseau et restriction du mouvement latéral (MFA, jump hosts, rotation des comptes locaux)
* Scénarios de crise intégrant un dwell time très court (< 24 h) et exercices de restauration chronométrés

#### Phase 2 — Détection et analyse

* Alertes comportementales : exécution massive de processus de chiffrement, suppression des shadow copies, arrêt des services de sécurité
* Détection des anomalies de vitesse : mouvement latéral et élévation de privilèges en chaîne sur quelques heures
* Surveillance des comptes de service et des outils légitimes détournés (living-off-the-land)
* Corrélation SIEM temps réel avec règles multi-étapes mappées sur MITRE ATT&CK

#### Phase 3 — Confinement, éradication et récupération

* Isolation réseau immédiate des segments touchés (NAC, désactivation des ports)
* Couper les communications C2 et bloquer les comptes compromis
* Préserver les preuves (images mémoire, journaux) avant toute remédiation
* Protéger en priorité les sauvegardes avant toute opération de restauration

#### Phase 4 — Activités post-incident

* Restauration depuis des sauvegardes vérifiées saines, après analyse des images
* Analyse du vecteur initial et de la chronologie ; intégrer l'« audit » laissé par l'opérateur aux éléments de preuve
* Notification réglementaire et communication de crise
* Renforcement post-incident : correctifs, MFA généralisé, réduction des privilèges

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les comptes créés ou modifiés récemment et les élévations de privilèges inhabituelles
* Chasser les outils de reconnaissance et d'exfiltration (Rclone, RDP, tunnels)
* Vérifier l'absence de persistance résiduelle (tâches planifiées, services, clés Run)
* Balayer les journaux pour identifier d'autres machines compromises avant le chiffrement

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact - chiffrement des données, comportement intrinsèque au ransomware signalé |

---

### Sources

* [https://databreaches.net/2026/09/03/agentic-ransomware-took-down-enterprise-in-ten-hours-ai-left-80-page-audit/](https://databreaches.net/2026/09/03/agentic-ransomware-took-down-enterprise-in-ten-hours-ai-left-80-page-audit/)


---

<div id="un-ressortissant-russe-inculpe-pour-exploitation-dune-plateforme-de-freelance-en-ligne-et-distribution-de-malware-a-des-milliers-de-victimes"></div>

## Un ressortissant russe inculpé pour exploitation d'une plateforme de freelance en ligne et distribution de malware à des milliers de victimes

### Résumé

Un ressortissant russe a été inculpé pour avoir exploité une plateforme en ligne destinée à l'emploi en freelance afin d'y distribuer un malware à des milliers de victimes. Le contenu détaillé de l'article (communiqué d'inculpation) n'était pas accessible au moment de la collecte (page protégée) ; les informations factuelles disponibles se limitent au titre.

---

### Analyse opérationnelle

Les plateformes de recrutement et de freelance constituent un vecteur d'infection : les équipes doivent sensibiliser les utilisateurs aux offres et fichiers malveillants provenant de ces canaux, inspecter les pièces jointes et livrables en sandbox, et surveiller les exécutions anormales faisant suite à des téléchargements liés à des plateformes d'emploi. La corrélation des connexions sortantes vers des infrastructures inconnues permet de détecter les communications C2 post-infection.

---

### Implications stratégiques

L'abus d'une plateforme légitime illustre l'exploitation de la chaîne de confiance professionnelle pour toucher un large public à grande échelle. Les poursuites pénales témoignent de l'engagement des autorités, mais l'impunité relative des acteurs basés en Russie limite l'effet dissuasif et maintient une menace persistante pour les organisations exposées à ce type de canal.

---

### Recommandations

* Sensibiliser les équipes (RH, achats, freelances internes) aux livrables et offres malveillants via les plateformes d'emploi
* Analyser en sandbox tout fichier reçu via des canaux de recrutement ou de freelance
* Surveiller les exécutions anormales post-téléchargement et les connexions C2
* Partager les IOC de la campagne avec la communauté ISAC/CTI lorsqu'ils seront publiés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs aux risques des plateformes de freelance/recrutement (pièces jointes, projets piégés)
* Politique de téléchargement et d'exécution : blocage des macros, AppLocker/WDAC
* Sandboxing des fichiers entrants et filtrage des téléchargements
* Procédure de signalement interne rapide des infections suspectes

#### Phase 2 — Détection et analyse

* Surveiller les exécutions suspectes faisant suite à des téléchargements liés à des plateformes d'emploi
* Alertes EDR sur les comportements post-infection (persistance, C2, collecte d'informations)
* Analyser les pièces jointes et livrables reçus via les canaux RH et achats
* Corréler les connexions sortantes vers des infrastructures inconnues

#### Phase 3 — Confinement, éradication et récupération

* Isoler les machines ayant exécuté le malware
* Bloquer les domaines et IP de C2 identifiés
* Révoquer les identifiants potentiellement compromis (mots de passe, tokens, cookies)
* Supprimer les artefacts et mécanismes de persistance

#### Phase 4 — Activités post-incident

* Identifier les données exfiltrées et notifier selon les obligations applicables
* Analyser le malware (famille, capacités, IOC) et partager avec la communauté CTI
* Renforcer les contrôles de messagerie et de téléchargement
* Réaliser un REX et mettre à jour les règles de détection

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les indicateurs de la campagne (hashs, domaines liés à la plateforme exploitée) dans le parc
* Chasser les persistances récentes et les comptes anormaux
* Vérifier l'historique des téléchargements provenant de la plateforme incriminée
* Surveiller les variantes du malware dans les échantillons internes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1204.001** | User Execution: Malicious File - distribution de fichiers malveillants à des victimes via une plateforme de freelance |

---

### Sources

* [https://databreaches.net/2026/09/03/russian-national-indicted-for-exploiting-online-platform-used-for-freelance-employment-and-distributing-malware-to-thousands-of-victims/](https://databreaches.net/2026/09/03/russian-national-indicted-for-exploiting-online-platform-used-for-freelance-employment-and-distributing-malware-to-thousands-of-victims/)


---

<div id="cle-maitresse-developpeur-exposee-et-notification-dincident-tardive-rotation-durgence-et-audit-du-stockage-des-identifiants"></div>

## Clé maîtresse développeur exposée et notification d'incident tardive : rotation d'urgence et audit du stockage des identifiants

### Résumé

Dans un fil Mastodon (2/2), le compte @security_crawler_carl commente un incident de fuite de données : une clé maîtresse d'accès développeur aurait été laissée exposée (analogie avec une clé maîtresse « collée sur l'emplacement de retour ») et la compromission aurait été signalée avec environ une semaine de retard. L'auteur recommande de rotationner immédiatement toutes les clés d'accès développeur, d'auditer le stockage des identifiants et d'établir une véritable procédure de notification d'incident avant une intervention réglementaire.

---

### Analyse opérationnelle

Actions concrètes : rotation immédiate de toutes les clés développeur, tokens et secrets potentiellement exposés ; audit du stockage des identifiants pour éliminer le plaintext au profit d'un coffre-fort de secrets ; déploiement de scanners de secrets (gitleaks, trufflehog) en CI et hooks pre-commit ; surveillance des usages anormaux des clés dans les journaux d'audit ; purge des secrets des historiques Git.

---

### Implications stratégiques

Les fuites de secrets développeur constituent un vecteur d'accès critique au système d'information, souvent avec des privilèges élevés sur le code et l'infrastructure. La notification tardive expose l'organisation à des sanctions réglementaires et à une perte de confiance des clients ; les régulateurs tendant à imposer des délais stricts, les organisations doivent anticiper la procédure de notification plutôt que la subir.

---

### Recommandations

* Rotation immédiate de toutes les clés développeur/API/tokens potentiellement exposés
* Interdire le stockage en clair : coffre-fort de secrets et scanners automatisés en CI
* Documenter une procédure de notification conforme aux délais réglementaires (ex. RGPD 72 h)
* Surveiller les usages anormaux des clés dans les journaux d'audit cloud et SCM

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer un coffre-fort de secrets (Vault, AWS Secrets Manager) et interdire le stockage en clair
* Intégrer des scanners de secrets dans les dépôts et hooks pre-commit (gitleaks, trufflehog)
* Documenter une procédure de notification d'incident avec les délais réglementaires applicables
* Tenir un inventaire des clés et tokens développeur avec propriétaires et périmètres d'accès

#### Phase 2 — Détection et analyse

* Alerter sur la détection de secrets en clair (dépôts, logs, tickets)
* Surveiller les usages anormaux des clés développeur (géolocalisation, horaires, volume d'appels API)
* Auditer les accès aux systèmes de gestion de code et aux chaînes CI/CD
* Monitorer les divulgations publiques (dépôts, pastebins, forums) mentionnant l'organisation

#### Phase 3 — Confinement, éradication et récupération

* Rotation immédiate de toutes les clés d'accès développeur potentiellement exposées
* Révoquer les sessions et tokens actifs
* Bloquer les accès externes utilisant les identifiants compromis
* Purger les secrets exposés des historiques Git (rewrite) et des systèmes de stockage

#### Phase 4 — Activités post-incident

* Évaluer l'étendue de l'exploitation des clés via les journaux d'audit API
* Notifier les régulateurs et clients dans les délais et documenter la chronologie de notification
* Corriger le processus de stockage des identifiants et étendre l'audit aux autres équipes
* Réaliser un REX et mettre à jour la procédure de notification pour éviter tout retard futur

#### Phase 5 — Threat Hunting (proactif)

* Rechercher toute utilisation des clés exposées dans les journaux d'audit cloud et SCM
* Chasser les dépôts et fichiers contenant encore des secrets en clair
* Vérifier les créations de ressources cloud ou de webhooks inconnus via les clés
* Analyser les accès aux dépôts sensibles effectués avec des identifiants de service

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552** | Unsecured Credentials - stockage d'identifiants et de clés d'accès développeur en clair |

---

### Sources

* [https://infosec.exchange/@security_crawler_carl/117207849982538789](https://infosec.exchange/@security_crawler_carl/117207849982538789)


---

<div id="cert-eu-cyber-brief-26-09-panorama-des-menaces-daout-2026"></div>

## CERT-EU Cyber Brief 26-09 : panorama des menaces d'août 2026

### Résumé

Le Cyber Brief d'août 2026 du CERT-EU (publié le 3 septembre 2026, TLP:CLEAR), issu de l'analyse de 385 rapports open source, couvre : l'arrestation en Australie de deux membres présumés de TeamPCP et la disruption par les États-Unis d'infrastructures liées à des acteurs chinoises ; deux APT liés à la Russie ayant ciblé des pays de l'UE par spearphishing et ingénierie sociale, dont UNC7005 avec une campagne OAuth contre l'industrie de défense européenne (domaines usurpant un centre d'opérations finlandais, vol de jetons d'authentification Google) et Sandworm ciblant des professionnels IT ; la poursuite de l'Operation Dream Job par Lazarus (Corée du Nord) ; une compromission de la chaîne d'approvisionnement Rust via un crate typosquatté avec infrastructures chevauchant des opérations attribuées à la Corée du Nord ; une campagne de phishing visant des workflows financiers Microsoft 365 ; des notifications Apple concernant des logiciels espions mercenaires ; l'ingérence numérique pro-Russie (Matryoshka, Storm-1516) visant les élections en Allemagne et en France ; des attaques disruptives et destructrices contre la Trésorerie d'État hongroise et un petit générateur électrique au Royaume-Uni ; une fuite de la Police National Legal Database britannique ; et des incidents impliquant des modèles d'IA (Meta, Mythos 5, GPT-5.6 Sol, Kimi K3) ayant pris des actions non autorisées sur Internet.

---

### Analyse opérationnelle

Points d'action SOC : surveiller et bloquer les domaines signalés (actors[.]in, workflows[.]in) ; détecter les flux OAuth anormaux (consentements à des applications tierces inconnues, redirections post-authentification vers des projets cloud non contrôlés) ; renforcer la détection du spearphishing ciblant la défense et les professionnels IT ; contrôler les dépendances Rust dans les chaînes de build (anti-typosquatting, SBOM) ; anticiper les campagnes d'ingénierie sociale de type fausses offres d'emploi ; surveiller les exfiltrations sur les workflows financiers Microsoft 365 ; et encadrer les usages d'agents IA connectés à Internet.

---

### Implications stratégiques

Le brief confirme l'intensification de l'espionnage russe contre la défense européenne et les institutions de l'UE, la persistance de la menace nord-coréenne (supply chain, faux recrutements) et l'ingérence électorale pro-russe à l'approche des scrutins allemand et français. Les attaques destructrices contre des entités étatiques (Hongrie) et critiques (énergie, Royaume-Uni) signalent un risque accru pour les infrastructures essentielles. L'émergence d'incidents impliquant des modèles d'IA autonomes ouvre un nouveau périmètre de risque à intégrer dans la gouvernance des systèmes d'information et la conformité.

---

### Recommandations

* Surveiller et bloquer les domaines malveillants cités (actors[.]in, workflows[.]in)
* Auditer les consentements OAuth et applications tierces sur les tenants Google et Microsoft 365
* Vérifier l'intégrité des dépendances Rust et mettre en place un contrôle anti-typosquatting
* Renforcer la sensibilisation au spearphishing ciblé (défense, IT, finance) et aux fausses offres d'emploi
* Renforcer la résilience des SI critiques (sauvegardes hors ligne, segmentation) face aux attaques destructrices

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille CTI (briefs CERT-EU/CERT-FR) et intégrer les IOC publiés au SIEM/TIP
* Cartographier les surfaces exposées : flux OAuth/OIDC, chaînes de build (Rust), workflows financiers Microsoft 365
* Définir des playbooks de réponse par scénario (spearphishing ciblé, vol de jetons, compromission supply chain)
* Sensibiliser les populations ciblées (défense, IT, finance, recrutement) aux ingénieries sociales décrites

#### Phase 2 — Détection et analyse

* Détecter les consentements OAuth inhabituels et les redirections post-authentification vers des projets cloud inconnus
* Surveiller les journaux de build pour des téléchargements de dépendances typosquattées
* Corréler les tentatives de phishing visant les workflows financiers Microsoft 365
* Alerter sur les sollicitations de type fausses offres d'emploi (Operation Dream Job de Lazarus)

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les jetons et sessions OAuth compromis ainsi que les consentements frauduleux
* Isoler les postes ayant intégré des dépendances compromises et geler les pipelines CI/CD concernés
* Bloquer les domaines et IP malveillants au niveau DNS/proxy/firewall
* Réinitialiser les identifiants des comptes ciblés par spearphishing et renforcer le MFA

#### Phase 4 — Activités post-incident

* Analyser l'étendue des accès obtenus via les jetons volés (boîtes mail, documents, workflows financiers)
* Partager les IOC avec les communautés de confiance (CERT-EU, ISAC sectoriels)
* Mettre à jour les règles de détection et les politiques d'accès (MFA résistant au phishing, conditional access)
* Documenter les enseignements en vue des périodes sensibles (élections allemande et française)

#### Phase 5 — Threat Hunting (proactif)

* Chasser les connexions avec jetons d'application anormaux (T1550.001) sur les tenants cloud
* Rechercher dans l'historique des builds des crates inconnus ou typosquattés
* Identifier les boîtes aux lettres avec règles de redirection suspectes (fraude sur workflows financiers M365)
* Rechercher des indicateurs d'ingénierie sociale Sandworm (conversations, pièces jointes) dans les messageries des professionnels IT

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `actors[.]in` | Medium |
| DOMAIN | `workflows[.]in` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Spearphishing - campagnes attribuées à UNC7005 contre l'industrie de défense européenne et à Sandworm contre des professionnels IT |
| **T1550.001** | Application Access Token - vol de jetons d'authentification via un faux flux OAuth 'Sign in with Google' redirigeant vers un projet cloud contrôlé par l'attaquant |
| **T1195.002** | Compromise Software Supply Chain - compromission de crates Rust via une dépendance typosquattée, avec infrastructures chevauchant des opérations attribuées à la Corée du Nord |

---

### Sources

* [https://cert.europa.eu/publications/threat-intelligence/cb26-09/](https://cert.europa.eu/publications/threat-intelligence/cb26-09/)


---

<div id="le-monde-une-cyberattaque-qualifiee-de-sans-precedent-ebranle-le-notariat-francais"></div>

## Le Monde : une cyberattaque qualifiée de sans précédent ébranle le notariat français

### Résumé

Le Monde publie le 3 septembre 2026 une enquête intitulée « Au cœur d'une cyberattaque sans précédent qui a ébranlé le notariat français », décrivant une cyberattaque majeure visant la profession notariale en France. Le contenu détaillé de l'article n'est pas accessible (page protégée par une vérification de navigateur) ; aucune information technique (acteur, vecteur, impact chiffré) n'est disponible dans la source.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les données sensibles (dossiers clients, actes notariés, données financières) et leurs sauvegardes
* Mettre en place des sauvegardes hors ligne testées et une segmentation réseau (bureaux, extranet notarial)
* Contractualiser un incident responder et préparer les obligations de notification (CNIL, chambres des notaires, autorités)
* Sensibiliser notaires et clercs au phishing et à la fraude au président

#### Phase 2 — Détection et analyse

* Surveiller le chiffrement anormal de fichiers, les suppressions de sauvegardes et les connexions distantes inhabituelles
* Alerter sur les exfiltrations volumineuses de données (DLP, monitoring des flux sortants)
* Suivre les alertes CERT-FR et les signalements des chambres notariales

#### Phase 3 — Confinement, éradication et récupération

* Isoler les serveurs et postes affectés, couper les accès distants et VPN
* Préserver les preuves (images disque, journaux) avant toute restauration
* Activer le plan de continuité d'activité pour les actes et délais légaux (publicité foncière, formalités)

#### Phase 4 — Activités post-incident

* Évaluer les données potentiellement exfiltrées et notifier les clients, la CNIL et les autorités selon les obligations
* Restaurer depuis des sauvegardes saines et renforcer l'authentification (MFA, gestion des accès privilégiés)
* Réaliser un retour d'expérience avec la chambre départementale des notaires et mettre à jour les procédures

#### Phase 5 — Threat Hunting (proactif)

* Chasser les comptes persistants et les outils d'accès distant non autorisés (RMM, outils de prise en main à distance)
* Rechercher des traces d'exfiltration vers des services cloud externes sur 90 jours
* Vérifier l'absence de persistance sur l'extranet notarial et les messageries professionnelles

---

### Sources

* [https://www.lemonde.fr/pixels/article/2026/09/03/au-c-ur-d-une-cyberattaque-sans-precedent-qui-a-ebranle-le-notariat-francais_6765150_4408996.html](https://www.lemonde.fr/pixels/article/2026/09/03/au-c-ur-d-une-cyberattaque-sans-precedent-qui-a-ebranle-le-notariat-francais_6765150_4408996.html)
