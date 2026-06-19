# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [FortiBleed : exposition massive d'identifiants Fortinet à l'échelle mondiale](#fortibleed-exposition-massive-didentifiants-fortinet-a-lechelle-mondiale)
  * [Botnet Popa : un réseau de millions de TV boxes Android relié au fournisseur de proxy résidentiel NetNut](#botnet-popa-un-reseau-de-millions-de-tv-boxes-android-relie-au-fournisseur-de-proxy-residentiel-netnut)
  * [Tendances de threat intelligence juin 2026 : ClearFake, Kali365 et TeamPCP dominent le paysage](#tendances-de-threat-intelligence-juin-2026-clearfake-kali365-et-teampcp-dominent-le-paysage)
  * [ART-004](#art-004)
  * [Un hacker canadien plaide coupable pour une cyberattaque contre un site républicain du Texas](#un-hacker-canadien-plaide-coupable-pour-une-cyberattaque-contre-un-site-republicain-du-texas)
  * [Le HHS OCR règle une enquête ransomware contre Spencer Gifts Health Plan pour 450 000 dollars et un plan d'action corrective](#le-hhs-ocr-regle-une-enquete-ransomware-contre-spencer-gifts-health-plan-pour-450-000-dollars-et-un-plan-daction-corrective)
  * [Royaume-Uni : HCRG notifie enfin les patients d'une attaque ransomware plus d'un an après l'incident](#royaume-uni-hcrg-notifie-enfin-les-patients-dune-attaque-ransomware-plus-dun-an-apres-lincident)
  * [Nintendo visé par une demande de rançon de 2 millions de dollars du groupe ShadowBytes](#nintendo-vise-par-une-demande-de-rancon-de-2-millions-de-dollars-du-groupe-shadowbytes)
  * [Un échantillon malveillant passe inaperçu pour la plupart des éditeurs AV, seuls Rise et MalwareBytes le détectent](#un-echantillon-malveillant-passe-inapercu-pour-la-plupart-des-editeurs-av-seuls-rise-et-malwarebytes-le-detectent)
  * [Un malware « slop IA » distribué via Discord désassemblé en quelques secondes](#un-malware-slop-ia-distribue-via-discord-desassemble-en-quelques-secondes)
  * [Dashlane révèle un brute-force ciblant le flux d'enregistrement d'appareils, moins de 20 coffres chiffrés exposés](#dashlane-revele-un-brute-force-ciblant-le-flux-denregistrement-dappareils-moins-de-20-coffres-chiffres-exposes)
  * [Accord à plusieurs millions de dollars conclu suite à la cyberattaque LockBit contre MCNA Dental ayant touché près de 9 millions de personnes, dont des enfants](#accord-a-plusieurs-millions-de-dollars-conclu-suite-a-la-cyberattaque-lockbit-contre-mcna-dental-ayant-touche-pres-de-9-millions-de-personnes-dont-des-enfants)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'activité CTI du jour demeure intense avec 18 signalements liés aux threat actors, confirmant une pression soutenue des groupes malveillants sur le tissu numérique. Le déséquilibre entre les vulnérabilités (16) et les brèches de données (6) traduit un volume élevé de CVE divulguées dont l'exploitation reste pour l'instant en deçà du potentiel offensif observé. La veille géopolitique reste discrète (3 éléments) mais conserve son rôle d'amplificateur contextuel sur la menace cyber. La seule entrée réglementaire invite à la vigilance sur les obligations de conformité, notamment en matière de notification et de durcissement. L'ensemble dessine une posture défensive privilégiant le patch management et la surveillance comportementale, tout en maintenant une attention sur les mouvements de threat actors en quête d'initial access.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Icarus** | SaaS, Retail, Technologie | Exploitation de vulnérabilités ou de jetons OAuth de fournisseurs tiers (supply chain attack), vol de données depuis des instances Salesforce, extorsion par menace de publication (double extorsion). | T1078, T1119, T1041, T1590, T1657, T1530, T1567 | [https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/) |
| **ShinyHunters** | Retail, SaaS, Cloud | Intrusion dans des environnements cloud/SaaS, exfiltration massive de données client, extorsion par menace de publication ou de revente. | T1657, T1530, T1567 | [https://haveibeenpwned.com/Breach/RalphLauren](https://haveibeenpwned.com/Breach/RalphLauren) |
| **Acteur non attribué (Blue Fish Pediatrics)** | Santé, Pédiatrie | Accès non autorisé à des données PHI, exfiltration et notification tardive. | T1530, T1647, T1565 | [https://databreaches.net/2026/06/18/blue-fish-pediatrics-notifies-41485-texans-about-data-breach-last-year/](https://databreaches.net/2026/06/18/blue-fish-pediatrics-notifies-41485-texans-about-data-breach-last-year/)<br>[https://verisizintisi.com/en/blog/2026-06-19-blue-fish-pediatrics-discloses-data-breach-affecting-41000-a-year-later](https://verisizintisi.com/en/blog/2026-06-19-blue-fish-pediatrics-discloses-data-breach-affecting-41000-a-year-later) |
| **Groupe d'extorsion (revendication One Medical)** | Santé, Services numériques grand public | Revendication de possession de données volées, tentative d'extorsion, menace de publication. | T1530, T1657, T1565 | [https://databreaches.net/2026/06/18/amazon-owned-one-medical-faces-alleged-8-8tb-data-breach/](https://databreaches.net/2026/06/18/amazon-owned-one-medical-faces-alleged-8-8tb-data-breach/) |
| **Acteur non attribué (Texas Government)** | Gouvernement, Administration | Compromission de comptes ou de systèmes gouvernementaux, exfiltration de données d'identité à grande échelle. | T1530, T1078, T1041 | [https://databreaches.net/2026/06/18/texas-government-data-breach-allowed-hackers-to-steal-3-million-drivers-licenses-and-passports/](https://databreaches.net/2026/06/18/texas-government-data-breach-allowed-hackers-to-steal-3-million-drivers-licenses-and-passports/) |
| **Incident Adama (Éthiopie) – mauvaise configuration** | Gouvernement, Administration locale | Mauvaise configuration d'un service exposant des données de citoyens en libre accès (responsible disclosure). | T1530, T1592, T1593 | [https://infosec.exchange/@chum1ng0/116774183668241325](https://infosec.exchange/@chum1ng0/116774183668241325)<br>[https://write-ups.security-chu.com/2026/06/Adama-Service-with-Data-Breach.html](https://write-ups.security-chu.com/2026/06/Adama-Service-with-Data-Breach.html) |
| **Acteurs russophones (FortiBleed / Fortinet)** | Entreprise, Télécommunications, Secteur régulé | Exploitation de vulnérabilités FortiGate (FortiBleed), vol de hash d'identifiants, craquage hors ligne, attaques par credential stuffing/brute force. | T1078.001, T1110.002, T1110.003, T1110.004, T1595.002, T1046, T1552.001, T1589.002 | [https://fieldeffect.com/blog/fortibleed-exposes-fortinet-credentials](https://fieldeffect.com/blog/fortibleed-exposes-fortinet-credentials) |
| **Opérateurs du botnet Popa (NetNut / Alarum Technologies)** | Grande consommation, Mobile, Marketing digital | Pré chargement de maliciels sur appareils Android, mise à disposition d'un réseau de proxy résidentiel, fraude publicitaire, scraping et détournement de comptes. | T1584.005, T1090, T1090.001, T1071.001, T1571, T1189, T1199, T1606, T1114 | [https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/](https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/) |
| **Écosystème ClearFake / Kali365 / TeamPCP / Scarlet Goldfinch** | Grande consommation, Développeurs, macOS, Cloud (Microsoft 365) | Injection JavaScript (ClearFake), faux CAPTCHA / ClickFix, phishing OAuth device code, supply chain attacks sur registres npm/PyPI, distribution de stealers Windows/macOS, persistance planifiée. | T1189, T1059.001, T1059.003, T1204.002, T1027, T1556.006, T1528, T1078.004, T1550.001, T1195.002, T1195.001, T1053.005, T1218.014, T1105 | [https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/) |
| **Hacker canadien (site du Parti républicain du Texas)** | Politique, Administration | Attaque Web (phishing / compromission applicative), défiguration ou compromission d'un site politique. | T1566, T1071 | [https://databreaches.net/2026/06/18/canadian-hacker-pleads-guilty-to-charges-for-cyberattack-on-texas-republican-website/](https://databreaches.net/2026/06/18/canadian-hacker-pleads-guilty-to-charges-for-cyberattack-on-texas-republican-website/) |
| **Acteur ransomware non attribué (Spencer Gifts Health Plan)** | Santé, Retail | Chiffrement de systèmes, reconnaissance, exfiltration, double extorsion. | T1486, T1083, T1059 | [https://databreaches.net/2026/06/18/hhs-o%ef%ac%83ce-for-civil-rights-settles-ransomware-investigation-with-spencer-gifts-health-plan-for-450k-corrective-action-plan/](https://databreaches.net/2026/06/18/hhs-o%ef%ac%83ce-for-civil-rights-settles-ransomware-investigation-with-spencer-gifts-health-plan-for-450k-corrective-action-plan/) |
| **Acteur ransomware non attribué (HCRG)** | Santé, Public | Chiffrement, exfiltration, fuite de données et extorsion. | T1486, T1567, T1657 | [https://databreaches.net/2026/06/18/uk-more-than-one-year-later-hcrg-is-first-notifying-patients-of-ransomware-attack/](https://databreaches.net/2026/06/18/uk-more-than-one-year-later-hcrg-is-first-notifying-patients-of-ransomware-attack/) |
| **ShadowBytes** | Jeux vidéo, Divertissement, Entreprise | Ransomware + extorsion par fuite de données, pression financière directe sur la victime. | T1486, T1657, T1567 | [https://gamesbriefly.news/nintendo-gets-hit-with-a-2-million-ransom-demand-and-the-final-boss-is-a-group-c](https://gamesbriefly.news/nintendo-gets-hit-with-a-2-million-ransom-demand-and-the-final-boss-is-a-group-c) |
| **Acteur non attribué (échantillon malveillant éducation)** | Éducation | Code obfusqué, scripting, techniques d'évasion anti sandbox. | T1027, T1059, T1497 | [https://t.me/vxunderground/8971](https://t.me/vxunderground/8971) |
| **Acteur non attribué (malware Discord / Electron)** | Communautés Discord, Utilisateurs grand public | Ingénierie sociale, application Discord compromise (Electron), obfuscation, IA générative pour la charge utile. | T1204, T1059, T1027 | [https://t.me/vxunderground/8970](https://t.me/vxunderground/8970) |
| **Acteur non attribué (Dashlane)** | Cybersécurité, Grand public, Entreprise | Brute force / réutilisation de mots de passe, compromission de comptes, vol de coffres chiffrés. | T1110, T1078, T1555 | [https://www.pcmag.com/news/password-manager-dashlane-reveals-how-a-hacker-stole-encrypted-vaults](https://www.pcmag.com/news/password-manager-dashlane-reveals-how-a-hacker-stole-encrypted-vaults) |
| **LockBit** | Santé, Industrie, Services publics, Entreprise | Ransomware + double extorsion (fuite + chiffrement), exploitation de comptes valides, affilé / RaaS. | T1486, T1657, T1078 | [https://www.healthcareinfosecurity.com/](https://www.healthcareinfosecurity.com/) |
| **Outils Red Team / recherche offensive (ADCS)** | Recherche en sécurité, Red Team | Outils de post-exploitation ADCS (Certify), encodeurs de shellcode. |  | [https://www.reddit.com/r/redteamsec/comments/1u9s78c/](https://www.reddit.com/r/redteamsec/comments/1u9s78c/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Asie du Sud-Est, Indonésie, Chine** | Mines et métallurgie / Industrie du nickel | Souveraineté minière et rapport de force entre Jakarta et les groupes chinois (Tsingshan, Huayou Cobalt, Brunp) sur la chaîne de valeur du nickel | En mai 2026, la Chambre de commerce chinoise en Indonésie a adressé au président Prabowo Subianto une lettre de protestation formelle copiée à l'ambassade de Chine. Les signataires — Tsingshan, Zhejiang Huayou Cobalt et Brunp — sont les groupes qui ont financé et construit l'industrialisation nickélifère indonésienne. Leur plainte porte sur les quotas de production, la révision du prix de référence du minerai et la hausse des royalties. Ce retournement est stratégique : les architectes de la domination indonésienne sur le marché mondial du nickel se retrouvent contraints de protester auprès d'un État qu'ils pensaient avoir rendu dépendant d'eux. Jakarta dispose désormais d'un levier de négociation réel et a commencé à l'utiliser, traduisant une volonté de reprendre le contrôle sur la rente minière et de rééquilibrer le partenariat sino-indonésien au profit des intérêts nationaux. | [https://www.iris-france.org/nickel-indonesien-la-souverainete-miniere-a-lepreuve-de-ses-propres-contradictions/](https://www.iris-france.org/nickel-indonesien-la-souverainete-miniere-a-lepreuve-de-ses-propres-contradictions/) |
| **Moyen-Orient, Iran, États-Unis, Israël, Golfe Persique** | Diplomatie / Sécurité internationale / Énergie (détroit d'Ormuz) | Ouverture de négociations de paix entre Washington et Téhéran après trois mois de guerre, et perspectives d'un accord sur le nucléaire et la sécurité maritime | L'Iran et les États-Unis ont annoncé le 14 juin 2026 un protocole d'accord devant être signé le 19 juin à Genève. Le texte prévoirait la réouverture du détroit d'Ormuz et la levée du blocus américain visant les ports iraniens. Plusieurs points restent en suspens, notamment le programme nucléaire iranien. Sur le plan intérieur, le régime iranien, confronté début 2026 à la plus grave crise de légitimité depuis la révolution (répression des manifestations de janvier ayant fait des milliers de morts), sort paradoxalement renforcé du conflit : la guerre a ravivé le réflexe nationaliste et consolidé la position des autorités, les scénarios israéliens de changement de régime ne s'étant pas concrétisés. En revanche, la situation économique s'est fortement dégradée : l'inflation atteindrait au moins 80 % en mai 2026 selon la Banque centrale d'Iran (70 % prévu par le FMI sur l'année), après une stagnation de l'activité en 2025. Du côté américain, ces négociations marquent une rupture dans la posture de Washington et interrogent les limites de l'opération militaire de Donald Trump en Iran. | [https://www.iris-france.org/iran-etats-unis-un-accord-de-paix-est-il-possible/](https://www.iris-france.org/iran-etats-unis-un-accord-de-paix-est-il-possible/) |
| **Amériques, Amérique latine, Caraïbe, Cuba, États-Unis** | Diplomatie / Politique étrangère | Renforcement de la pression américaine sur Cuba et stratégie de changement de régime portée par Donald Trump en Amérique latine | L'administration Trump intensifie la pression sur Cuba et affiche ouvertement sa volonté de pousser à la chute du gouvernement cubain. Cette posture s'inscrit dans une politique étatsunienne plus large envers l'Amérique latine, marquée par le recours à la coercition économique et diplomatique pour imposer un changement de régime. Cette approche, analysée par Christophe Ventura (IRIS) dans un échange avec Pascal Boniface, soulève des questions sur la souveraineté des États latino-américains, la multilatéralité régionale et le risque de tensions accrues dans la zone caraïbe, dans un contexte où plusieurs gouvernements de la région résistent aux injonctions de Washington. | [https://www.iris-france.org/trump-main-basse-sur-lamerique-latine/](https://www.iris-france.org/trump-main-basse-sur-lamerique-latine/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Operation Endgame – phase SocGholish/Evil Corp | Europol, Eurojust, NHCTU (Pays-Bas), RCMP (Canada), FBI (États-Unis), BKA (Allemagne) | 2026-06-18 | International (UE, Amérique du Nord) | Operation Endgame – phase SocGholish/Evil Corp | Le 18 juin 2026, une nouvelle phase d'Operation Endgame, coordonnée par Europol et Eurojust, a ciblé le réseau de distribution de malwares SocGholish (alias FakeUpdates/GhoLoader), actif depuis 2017 et attribué au groupe cybercriminel russe Evil Corp (TA569). Les autorités ont assaini 14 971 sites WordPress compromis, saisi 106 serveurs et domaines, et transmis à Have I Been Pwned 154 527 adresses e-mail impactées accompagnées de plus d'un demi-million de mots de passe précédemment inconnus. SocGholish fonctionne par compromission de sites WordPress légitimes et usage de fausses mises à jour de navigateur pour livrer des charges utiles JScript, servant de vecteur d'accès initial à des ransomwares (WastedLocker, Hades, Macaw Locker, Phoenix CryptoLocker) et aux malwares Dridex, Doppelpaymer, Empire, Koadic, Chtonic, Azorult. L'opération s'inscrit dans la continuité des phases précédentes (Rhadamanthys, VenomRAT, Elysium, Smokeloader, AVCheck, DanaBot, IcedID, Pikabot, Trickbot, Bumblebee, SystemBC). Une analyse d'Infoblox indique que 55 % des clients cloud ont été exposés à SocGholish en 2026, touchant gouvernement, éducation et santé. | [https://www.bleepingcomputer.com/news/security/law-enforcement-nukes-socgholish-malware-from-nearly-15-000-sites/](https://www.bleepingcomputer.com/news/security/law-enforcement-nukes-socgholish-malware-from-nearly-15-000-sites/)<br>[https://haveibeenpwned.com/Breach/OperationEndgame4](https://haveibeenpwned.com/Breach/OperationEndgame4)<br>[https://otx.alienvault.com/pulse/6a3406813fdcd206dd6ba872](https://otx.alienvault.com/pulse/6a3406813fdcd206dd6ba872) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Technologie / SaaS (Market Intelligence & CRM)** | Klue (et clients Salesforce via intégration Klue Battlecards) | Données CRM Salesforce de multiples organisations clientes de Klue (enregistrements clients, données commerciales, potentiellement informations de contact et données de compte) | Inconnu | [https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/) |
| **Santé (Pédiatrie)** | Blue Fish Pediatrics (Texas) | Données personnelles et potentiellement médicales de 41 485 patients pédiatriques texans et leurs familles (probablement : noms, DOB, adresses, antécédents médicaux, informations d'assurance, numéros de sécurité sociale - à confirmer par la notification officielle) | 41485 | [https://databreaches.net/2026/06/18/blue-fish-pediatrics-notifies-41485-texans-about-data-breach-last-year/](https://databreaches.net/2026/06/18/blue-fish-pediatrics-notifies-41485-texans-about-data-breach-last-year/)<br>[https://verisizintisi.com/en/blog/2026-06-19-blue-fish-pediatrics-discloses-data-breach-affecting-41000-a-year-later](https://verisizintisi.com/en/blog/2026-06-19-blue-fish-pediatrics-discloses-data-breach-affecting-41000-a-year-later) |
| **Santé (Santé numérique / Télémedecine)** | One Medical (Amazon) | Allégation de 8.8 To de données : potentiellement PHI complètes (dossiers médicaux, prescriptions, labos), PII (noms, DOB, adresses, SSN), données d'assurance, historique de paiements et de téléconsultations | 8800000000000 | [https://databreaches.net/2026/06/18/amazon-owned-one-medical-faces-alleged-8-8tb-data-breach/](https://databreaches.net/2026/06/18/amazon-owned-one-medical-faces-alleged-8-8tb-data-breach/) |
| **Gouvernement / Administration publique (État du Texas)** | Gouvernement de l'État du Texas (Department of Public Safety / agence étatique) | 3 millions de permis de conduire et passeports texans : noms complets, dates de naissance, adresses, numéros de permis, photos, signatures, et potentiellement numéros de sécurité sociale (si inclus dans les enregistrements DMV) | 3000000 | [https://databreaches.net/2026/06/18/texas-government-data-breach-allowed-hackers-to-steal-3-million-drivers-licenses-and-passports/](https://databreaches.net/2026/06/18/texas-government-data-breach-allowed-hackers-to-steal-3-million-drivers-licenses-and-passports/) |
| **Gouvernement / Administration municipale (Éthiopie)** | Gouvernement de la ville d'Adama (Éthiopie) | ~29 Go de données citoyennes : actes de naissance, registres de mariage, titres fonciers, photos d'identité, dossiers administratifs | 29000000000 | [https://infosec.exchange/@chum1ng0/116774183668241325](https://infosec.exchange/@chum1ng0/116774183668241325)<br>[https://write-ups.security-chu.com/2026/06/Adama-Service-with-Data-Breach.html](https://write-ups.security-chu.com/2026/06/Adama-Service-with-Data-Breach.html) |
| **Retail / Mode (luxe)** | Ralph Lauren | Adresses e-mail (140 000), noms, numéros de téléphone, genres, tranches d'âge | 140000 | [https://haveibeenpwned.com/Breach/RalphLauren](https://haveibeenpwned.com/Breach/RalphLauren) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-20181** | 9.1 | 0.57% | FALSE | Cisco Identity Services Engine (ISE) et ISE-PIC — versions 3.3.x, 3.4.x (antérieures à 3.4 Patch 6), 3.5.x (antérieures à 3.5 Patch 3) | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Atteinte à la confidentialité (accès root, lecture de données sensibles), exécution de code arbitraire à distance, déni de service en déploiement mono-nœud, compromission complète du contrôle d'accès réseau (ISE étant l'autorité d'authentification). | Theoretical | Appliquer ISE 3.3 Patch 11, ISE 3.4 Patch 6, ou le hotfix 3.5 en attendant le Patch 4 prévu en août 2026. Restreindre l'accès à l'interface d'administration ISE à un réseau de gestion dédié, imposer MFA et segmentation. Auditer les comptes admin, surveiller les logs HTTP et événements système, et préparer un plan de retour en arrière (snapshots). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0772/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0772/)<br>[https://securityaffairs.com/193849/uncategorized/cisco-fixed-a-critical-ise-vulnerability-that-lets-attackers-to-gain-root-access.html](https://securityaffairs.com/193849/uncategorized/cisco-fixed-a-critical-ise-vulnerability-that-lets-attackers-to-gain-root-access.html)<br>[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-G5WP8vv](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-G5WP8vv) |
| **CVE-2026-8806** | 8.7 | N/A | FALSE | Mitsubishi Electric MELSEC iQ-F Series FX5-ENET/IP - module Ethernet, toutes versions | CWE-440 Expected Behavior Violation | Perte de disponibilité du module Ethernet, interruption potentielle de la communication avec l'automate, risque d'arrêt de la ligne de production ou du procédé industriel supervisé, pas d'impact direct sur l'intégrité ou la confidentialité des données. | Theoretical | Limiter le débit de communication vers le port Ethernet, appliquer les mises à jour firmware de Mitsubishi Electric lorsqu'elles sont disponibles, surveiller le trafic réseau pour détecter des anomalies, restreindre l'accès réseau au module via segmentation OT/IT. | [https://cvefeed.io/vuln/detail/CVE-2026-8806](https://cvefeed.io/vuln/detail/CVE-2026-8806) |
| **CVE-2026-8805** | 8.7 | N/A | FALSE | Mitsubishi Electric MELSEC iQ-F Series FX5-EIP EtherNet/IP module, versions 1.000 et antérieures | CWE-190 Integer Overflow or Wraparound | Arrêt de la communication EtherNet/IP, interruption potentielle du procédé industriel contrôlé par l'automate, risque d'arrêt de ligne de production, pas d'impact sur la confidentialité/intégrité des données. | Theoretical | Mettre à jour le firmware du module FX5-EIP dès la publication du correctif, limiter le nombre de connexions TCP simultanées, restreindre l'accès réseau au module EtherNet/IP via segmentation OT et ACL. | [https://cvefeed.io/vuln/detail/CVE-2026-8805](https://cvefeed.io/vuln/detail/CVE-2026-8805) |
| **CVE-2026-40624** | 9.8 | N/A | FALSE | Caméras AVer PTC500S, PTC115, PTC500+ et PTC115+ - interface web | CWE-552 | Exécution de code arbitraire à distance sur la caméra, compromission de la confidentialité (accès au flux vidéo, microphone), intégrité (modification firmware/configuration), disponibilité (rendre la caméra inutilisable), pivot potentiel vers le réseau interne. | Theoretical | Mettre à jour immédiatement le firmware des caméras AVer concernées, appliquer les correctifs de sécurité fournis par l'éditeur, restreindre l'accès réseau aux caméras, surveiller le trafic web entrant. | [https://cvefeed.io/vuln/detail/CVE-2026-40624](https://cvefeed.io/vuln/detail/CVE-2026-40624) |
| **MULTI-MITEL-2026-06** | N/A | N/A | FALSE | Mitel MiCollab versions 10.2.x antérieures à 10.2 SP1 FP2 (10.2.1.205), versions 9.8.x antérieures à 9.8 SP3 FP2 (9.8.3.203), MiVoice Business Solution Virtual Instance (MiVB SVI) versions 1.0 (sans derniers correctifs) et 2.x antérieures à 2.1.0.9-4 | Multiples vulnérabilités : RCE, SSRF, SQLi, contournement de politique de sécurité, atteinte intégrité et confidentialité | Exécution de code arbitraire à distance sur les serveurs de communication, compromission de la confidentialité des communications, atteinte à l'intégrité des données (CDR, configurations, comptes), contournement des contrôles de sécurité, pivot réseau potentiel vers le SI interne. | Theoretical | Appliquer les correctifs Mitel selon les versions cibles (MiCollab 10.2.1.205, 9.8.3.203, MiVB SVI 2.1.0.9-4) via le bulletin MISA-2026-0005, consulter l'avis CERT-FR CERTFR-2026-AVI-0770, restreindre l'accès réseau aux interfaces Mitel, surveiller les logs serveur, désactiver les services non utilisés. | [https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2026-0005](https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2026-0005)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0770/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0770/) |
| **MULTI-DRUPAL-2026-06** | N/A | N/A | FALSE | Drupal versions 10.5.x antérieures à 10.5.12, versions 10.6.x antérieures à 10.6.11, versions 11.2.x antérieures à 11.2.14, versions 11.3.x antérieures à 11.3.12. CVE associées : CVE-2026-55803, CVE-2026-55804, CVE-2026-55806, CVE-2026-55807, CVE-2026-55808. | Multiples vulnérabilités : RCE, SQLi, SSRF, XSS, contournement de politique de sécurité | Exécution de code arbitraire à distance sur le serveur web, compromission de la base de données (exfiltration via SQLi), contournement des contrôles d'accès, injection de contenu malveillant via XSS, pivot réseau potentiel vers le SI interne. | Theoretical | Mettre à jour Drupal vers 10.5.12, 10.6.11, 11.2.14 ou 11.3.12 selon la branche, appliquer les bulletins Drupal Security Advisory, renforcer la segmentation réseau et le WAF, surveiller les logs serveur. | [https://drupal.org/sa-core-2026-005](https://drupal.org/sa-core-2026-005)<br>[https://drupal.org/sa-core-2026-006](https://drupal.org/sa-core-2026-006)<br>[https://drupal.org/sa-core-2026-007](https://drupal.org/sa-core-2026-007)<br>[https://drupal.org/sa-core-2026-008](https://drupal.org/sa-core-2026-008)<br>[https://drupal.org/sa-core-2026-009](https://drupal.org/sa-core-2026-009)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0771/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0771/) |
| **MULTI-ATLASSIAN-2026-06** | N/A | N/A | FALSE | Multiples produits Atlassian : Confluence Server (CONFSERVER-103468, 103906, 103936, 104130 à 104199), Jira Service Management Server (JSDSERVER-16541 à 16632), Jira Software Server (JSWSERVER-26751 et suivants) | Multiples vulnérabilités (détails spécifiques par bulletin non disponibles dans l'avis) | Impact variable selon les CVE : compromission potentielle de la confidentialité des données (espaces Confluence, tickets Jira), intégrité des contenus, contournement de l'authentification, exécution de code potentielle selon les vulnérabilités sous-jacentes, pivot réseau vers le SI interne. | Theoretical | Appliquer immédiatement les correctifs Atlassian selon les bulletins référencés dans l'avis CERTFR-2026-AVI-0773, renforcer la segmentation réseau, activer l'authentification forte (SSO + MFA), surveiller les audit logs, restreindre l'accès réseau aux instances Atlassian. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0773/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0773/) |
| **MULTI-SPLUNK-AI-2026-06** | N/A | N/A | FALSE | Splunk AI Toolkit versions antérieures à 5.7.4. CVE associées : CVE-2026-20265, CVE-2026-20266. | Multiples vulnérabilités : exécution de code arbitraire à distance (RCE) et contournement de la politique de sécurité | Exécution de code arbitraire à distance sur le serveur Splunk, contournement de la politique de sécurité, accès potentiel à l'ensemble des logs et données indexées (y compris données de sécurité sensibles), pivot réseau vers le SI, sabotage possible du SIEM. | Theoretical | Mettre à jour Splunk AI Toolkit vers la version 5.7.4 ou ultérieure, appliquer les bulletins Splunk SVD-2026-0613 et SVD-2026-0614, renforcer la segmentation réseau du SIEM, surveiller les audit logs Splunk, restreindre l'accès à l'interface d'administration (port 8089). | [https://advisory.splunk.com/advisories/SVD-2026-0613](https://advisory.splunk.com/advisories/SVD-2026-0613)<br>[https://advisory.splunk.com/advisories/SVD-2026-0614](https://advisory.splunk.com/advisories/SVD-2026-0614)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0774/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0774/) |
| **VU#457458** | N/A | N/A | FALSE | Multiples applications UEFI signées par différents constructeurs : Acer (GRUB2 insmod, UEFI shell mm/dmpstore, Emdoor UEFI shell mm/setvar), AMD (UEFI shell mm/dmpstore), ASUS schenker-tech.de (XMG, UEFI shell mm/dmpstore), ECS (UEFI Shell mm/dmpstore), Getac (UEFI Shell mm/dmpstore), GIGABYTE Maibenben, et autres constructeurs | Bypass Secure Boot (BYOVD-style sur applications UEFI signées) - exécution de code arbitraire en pré-OS | Bypass complet de Secure Boot, exécution de code arbitraire durant la phase pré-boot avant chargement du système d'exploitation, persistance au niveau firmware (très difficile à détecter et à supprimer), modification de variables NVRAM sensibles, chargement de drivers non vérifiés, compromission totale de la chaîne de confiance. | Theoretical | Appliquer les mises à jour de la base DBX (UEFI Forbidden Signature Database) fournies par les constructeurs afin de révoquer la confiance accordée aux binaires UEFI vulnérables, consulter la liste complète des hashes révoqués dans la note VU#457458, mettre à jour le firmware UEFI/BIOS selon les recommandations constructeurs, surveiller les bulletins CERT/CC et publications ESET. | [https://kb.cert.org/vuls/id/457458](https://kb.cert.org/vuls/id/457458) |
| **CVE-2026-12048** | 9.3 | N/A | FALSE | pgAdmin 4 versions 6.0 à <9.16 | CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | Injection HTML/JavaScript arbitraire dans le DOM pgAdmin, redirection de l'onglet vers un site de phishing, vol de session, compromission potentielle d'informations d'identification de bases de données. Risque de pivot et d'ingénierie sociale rendue indétectable grâce à l'origine légitime de la fenêtre pgAdmin. | None | Mettre à jour pgAdmin 4 vers la version 9.16 ou ultérieure ; vérifier l'application de DOMPurify et des composants SafeMessage/SafeHtmlMessage ; restreindre les connexions aux serveurs PostgreSQL de confiance ; nettoyer les noms d'objets/colonnes suspects ; auditer les logs pour traquer des payloads XSS dans les erreurs et plans EXPLAIN. | [https://cvefeed.io/vuln/detail/CVE-2026-12048](https://cvefeed.io/vuln/detail/CVE-2026-12048) |
| **CVE-2026-12046** | 9.0 | N/A | FALSE | pgAdmin 4 versions 6.9 à <9.16 (mode serveur uniquement) | CWE-306 Missing Authentication for Critical Function | Exécution de code à distance non authentifiée en mode serveur pgAdmin, avec les privilèges du compte exécutant pgAdmin ; pivot potentiel vers l'hôte et les bases de données connectées. Risque amplifié en cas de SECRET_KEY faible, divulgué ou dans un répertoire sessions/ mal sécurisé. | None | Mettre à jour pgAdmin 4 vers 9.16 ou plus ; régénérer Flask SECRET_KEY et nettoyer le répertoire sessions/ ; durcir les permissions sur sessions/ ; segmenter réseau ; tester en mode serveur (le mode DESKTOP n'est pas affecté). | [https://cvefeed.io/vuln/detail/CVE-2026-12046](https://cvefeed.io/vuln/detail/CVE-2026-12046) |
| **CVE-2026-12045** | 9.0 | N/A | FALSE | pgAdmin 4 versions 9.13 à <9.16 (avec AI Assistant) | CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Modifications de données non autorisées en base ; escalade vers exécution de code sur le serveur PostgreSQL si le rôle utilisé par l'assistant dispose de privilèges élevés ; compromission de l'intégrité et de la confidentialité des données. | None | Mettre à jour pgAdmin 4 vers 9.16+ ; désactiver l'AI Assistant sur les instances non patchées ; appliquer le principe du moindre privilège sur le rôle utilisé par l'assistant ; nettoyer les contenus d'objets accessibles à l'AI Assistant ; surveiller les requêtes multi-instructions et les verbes de contrôle transactionnel. | [https://cvefeed.io/vuln/detail/CVE-2026-12045](https://cvefeed.io/vuln/detail/CVE-2026-12045) |
| **CVE-2026-35273** | 9.8 | 0.72% | TRUE | PeopleSoft PeopleTools — composant EMHub/PSEMHUB (versions 8.61 et 8.62) | Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Updates Environment Management). Supported versions that are affected are 8.61 and 8.62. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PeopleTools. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). | Compromission massive de données sensibles (étudiants, RH, recherche), RCE sur les serveurs PeopleSoft, pivot latéral vers l'AD, risque de double extorsion et de ransomware. | Active | Appliquer d'urgence le patch Oracle CSPU de juin 2026 ; désactiver EMHub ou retirer PSEMHUB selon l'architecture ; isoler du réseau les instances non patchées ; chasser les indicateurs de compromission depuis le 27 mai 2026 (meshagent64-azure-ops[.]exe, domaines C2 lookalike Azure, archives zstd) ; notifier les autorités et personnes concernées. | [https://thecyberthrone.in/2026/06/19/the-vulnerabilities-that-matter-in-oracles-june-2026-cspu/](https://thecyberthrone.in/2026/06/19/the-vulnerabilities-that-matter-in-oracles-june-2026-cspu/) |
| **CVE-2025-20701** | 8.8 | 3.40% | FALSE | Beats Studio Buds (Bluetooth) — puces Airoha Systems | CWE-863 Incorrect Authorization | Écoute clandestine de conversations, accès à l'historique d'appels/contacts, capacité à passer des appels arbitraires depuis l'appareil ciblé, atteinte à la confidentialité. | Theoretical | Mettre à jour le firmware des Beats Studio Buds (1B211) ; vérifier les correctifs sur les autres appareils Airoha ; désactiver le Bluetooth lorsqu'il n'est pas utilisé ; éviter les usages sensibles dans des lieux publics ; surveiller les bulletins Apple/Jabra/Bose/JBL/Sony/OnePlus/Google. | [https://arstechnica.com/apple/2026/06/apple-patches-high-severity-eavesdropping-vulnerability-in-beats-studio-buds/](https://arstechnica.com/apple/2026/06/apple-patches-high-severity-eavesdropping-vulnerability-in-beats-studio-buds/) |
| **CVE-2026-50195** | 8.8 | N/A | FALSE | containerd CRI Plugin (versions 1.7 à 2.3) - utilisé par Amazon EKS, ECS, Fargate, Bottlerocket, Amazon Linux | Empoisonnement de cache d'images via références de checkpoint non validées (image cache poisoning) | Exécution de code arbitraire entre pods sur les nœuds Kubernetes partagés, compromission potentielle de workloads multi-tenants, escalade vers le contrôle du nœud hôte, fuite de données entre locataires cloud. | None | Mettre à niveau containerd vers la version patchée publiée sur les advisories GitHub du projet upstream. Désactiver la fonctionnalité checkpoint/restore en atténuation. AWS déploie les correctifs sur les flottes EKS, ECS et Fargate ; les déploiements auto-hébergés sur EC2 ou on-prem doivent être patchés manuellement. | [https://aws.amazon.com/security/security-bulletins/rss/2026-046-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-046-aws/)<br>[https://github.com/advisories/GHSA-cvxm-645q-p574](https://github.com/advisories/GHSA-cvxm-645q-p574) |
| **CVE-2026-53488** | 8.3 | N/A | FALSE | containerd CRI Plugin (versions 1.7 à 2.3) - Amazon EKS, ECS, Fargate, Bottlerocket, Amazon Linux | Injection de commandes hôte via instructions LABEL non assainies dans la configuration d'image | Exécution arbitraire de commandes sur l'hôte du nœud via simple pull d'une image malveillante, compromission complète du nœud, pivot possible vers le cluster Kubernetes et autres workloads. | None | Aucune mitigation en dehors de la mise à niveau vers une version patchée de containerd. Il est impératif de mettre à jour containerd immédiatement et de restreindre les sources d'images via des politiques d'admission strictes (OPA, Kyverno, imagePolicyWebhook). | [https://aws.amazon.com/security/security-bulletins/rss/2026-046-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-046-aws/)<br>[https://github.com/advisories/GHSA-xhf5-7wjv-pqxp](https://github.com/advisories/GHSA-xhf5-7wjv-pqxp) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="fortibleed-exposition-massive-didentifiants-fortinet-a-lechelle-mondiale"></div>

## FortiBleed : exposition massive d'identifiants Fortinet à l'échelle mondiale

### Résumé technique

• Vecteur initial : credential stuffing et exploitation de fichiers de configuration FortiGate exposés sur Internet
• Cibles : interfaces SSL VPN (ports 443, 4443, 8443, 10443)
• Volume estimé : ~75 000 appliances, 21 000 domaines, 194 pays
• Données compromises : credentials administrateur hachés en SHA-256 (vulnérables au offline cracking)
• Atténuation : mise-à-jour FortiOS 7.2.11/7.4.8/7.6.1+ avec re-authentification pour activer PBKDF2
• Attribution présumée : acteurs russophones opérant une infrastructure de credential collection à grande échelle

---

### Analyse de l'impact

Entre le 13 et le 17 juin 2026, plusieurs chercheurs ont validé la découverte d'une infrastructure hébergeant un jeu de données contenant des identifiants potentiellement valides pour environ 75 000 pare-feu Fortinet FortiGate et passerelles SSL VPN. Baptisé FortiBleed, ce corpus couvre plus de 21 000 domaines répartis dans 194 pays, avec une concentration particulière en Inde, aux États-Unis et au Mexique. Les comptes d'entreprise sont les plus ciblés. L'activité de collecte, associée à des acteurs russophones, repose sur des processus automatisés exploitant les points d'accès Fortinet courants, notamment le port HTTPS 443 par défaut ainsi que des ports non-standard (4443, 8443, 10443). Des fichiers de configuration Fortinet exfiltrés depuis des équipements exposés ont été retrouvés sur un serveur opérationnel de l'attaquant, accompagnés d'outils d'automatisation et de listes de systèmes affectés. Ces fichiers ont permis d'extraire des credentials administrateur. De nombreux systèmes concernés utilisaient un hachage SHA-256, plus vulnérable au cracking hors-ligne, avant l'introduction du PBKDF2 dans les versions FortiOS 7.2.11, 7.4.8 et 7.6.1. La migration des hashes ne s'opère qu'après authentification post-mise-à-jour, prolongeant ainsi l'exposition. Cet incident confirme la tendance 2026 selon laquelle la majorité des compromissions reposent désormais sur l'abus d'identité plutôt que sur l'exploitation de malware, avec des datasets accumulés sur plusieurs années combinant leaks de configuration, phishing, credential stuffing et dumps darkweb.

---

### Recommandations

* Mettre à jour immédiatement toutes les appliances Fortinet vers FortiOS 7.2.11+, 7.4.8+ ou 7.6.1+ puis déclencher une re-authentification pour migrer les hashes vers PBKDF2
* Activer le MFA sur tous les comptes administrateurs et restreindre l'accès de management à des IP de confiance
* Restreindre l'exposition Internet des interfaces SSL VPN et auditer les ports 4443/8443/10443 via Shodan/Censys
* Vérifier la présence de vos domaines/emails/usernames dans la lookup-tool FortiBleed et révoquer les credentials affectés
* Implémenter une surveillance SIEM des tentatives d'authentification répétées et des connexions géographiquement incohérentes
* Centraliser l'authentification VPN via un IdP avec MFA forte et limiter les comptes locaux FortiGate

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier l'inventaire complet des appliances Fortinet FortiGate et passerelles SSL VPN exposées sur Internet
* Identifier les versions FortiOS et vérifier la conformité avec les versions 7.2.11, 7.4.8 et 7.6.1引入ant le hachage PBKDF2
* Segmenter et restreindre l'accès d'administration (management) à des sources IP de confiance via ACL / firewall
* Activer l'authentification multifacteur (MFA) sur tous les comptes administrateurs FortiGate
* Documenter les procédures de rotation des credentials et de ré-émission des certificats VPN
* Préparer des scripts de détection de brute-force contre les ports 443/4443/8443/10443

#### Phase 2 — Détection et analyse

* Rechercher dans les logs FortiGate les connexions réussies depuis des IP inhabituelles ou géographiquement incohérentes
* Détecter les tentatives d'authentification répétées sur les interfaces SSL VPN
* Identifier les accès administratifs hors heures ouvrées ou depuis des ASNs atypiques
* Rechercher la présence de domaines, emails ou usernames de l'organisation dans la liste de consultation FortiBleed
* Corréler les alertes SIEM avec les indicateurs de compromission (IP, ASN, user-agent) liés au threat actor russophone
* Vérifier les exports de configuration non autorisés depuis les équipements FortiGate

#### Phase 3 — Confinement, éradication et récupération

* Isoler temporairement les appliances Fortinet présentant des compromissions confirmées
* Révoquer immédiatement les comptes locaux etforcer la rotation des mots de passe administrateur
* Désactiver les sessions VPN actives et forcer la re-authentification avec MFA
* Basculer vers un compte administrateur de secours stocké hors-ligne
* Restreindre les flux entrants/sortants des appliances affectées pendant l'investigation
* Migrer les comptes utilisateurs vers une solution IdP centralisée avec authentification forte

#### Phase 4 — Activités post-incident

* Forcer la mise à jour FortiOS vers les versions 7.2.11+/7.4.8+/7.6.1+ puis demander une authentification pour migrer les hashes vers PBKDF2
* Auditer l'intégrité des fichiers de configuration et des certificats
* Rechercher des indicateurs de persistance (comptes fantômes, routes statiques inhabituelles, VPN SSL de novo)
* Réaliser un forensic complet des appliances suspectes (logs, mémoire, stockage)
* Communiquer aux parties prenantes et aux autorités réglementaires si des données personnelles sont exposées
* Mettre à jour les politiques de gestion des identités et durcir les baselines de configuration

#### Phase 5 — Threat Hunting (proactif)

* Chasser les comptes FortiGate présents dans les bases leaked-credentials (FortiBleed, collections Pastebin, marchés darkweb)
* Rechercher les configurations FortiGate exfiltrées vers des serveurs externes (C2 connus)
* Monitorer les ASNs et IP associées aux infrastructures russophones de credential harvesting
* Détecter les activités de credential stuffing via corrélation des logs VPN et patterns de réutilisation
* Auditer régulièrement l'exposition des interfaces de gestion (443, 4443, 8443, 10443) via Shodan/Censys
* Mettre en place des honeytokens FortiGate admin pour détecter les tentatives d'accès non autorisées

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://[:]4443` | Medium |
| URL | `hxxps://[:]8443` | Medium |
| URL | `hxxps://[:]10443` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.001** | Valid Accounts : Default Accounts |
| **T1110.002** | Brute Force : Password Cracking |
| **T1110.003** | Brute Force : Password Spraying |
| **T1110.004** | Brute Force : Credential Stuffing |
| **T1595.002** | Active Scanning : Vulnerability Scanning |
| **T1046** | Network Service Discovery |
| **T1552.001** | Credentials In Files |
| **T1589.002** | Gather Victim Identity Information : Email Addresses |

---

### Sources

* [https://fieldeffect.com/blog/fortibleed-exposes-fortinet-credentials](https://fieldeffect.com/blog/fortibleed-exposes-fortinet-credentials)


---

<div id="botnet-popa-un-reseau-de-millions-de-tv-boxes-android-relie-au-fournisseur-de-proxy-residentiel-netnut"></div>

## Botnet Popa : un réseau de millions de TV boxes Android relié au fournisseur de proxy résidentiel NetNut

### Résumé technique

• Vecteur initial : supply-chain (TV boxes Android vendues avec firmware compromis)
• Cibles : utilisateurs particuliers (réseau domestique transformé en nœud proxy)
• Volume : millions de boîtiers TV compromis, 1,4 M+ adresses IP utilisées pour du scraping
• Capacité : communications chiffrées persistantes, tunnels à la demande, relais de trafic frauduleux
• Attribution : infrastructure partagée avec NetNut / Alarum Technologies (NASDAQ : ALAR)
• Lien confirmé : Vo1d → Badbox 2.0 (disrupté en juillet 2025 par Google, HUMAN, Trend Micro) → Popa

---

### Analyse de l'impact

Depuis quatre ans, le botnet Popa, basé sur Android, a contraint des millions de boîtiers TV grand public à relayer du trafic Internet lié à de la fraude publicitaire, des prises de contrôle de comptes et du data-scraping massif. Des chercheurs de Qurium, HUMAN Security et Trend Micro ont établi un lien direct entre Popa et NetNut, fournisseur de proxy résidentiel opéré par la société israélienne cotée au NASDAQ Alarum Technologies Ltd (ALAR). Popa est un composant associé au botnet Vo1d, ciblant des TV boxes Android non officielles pré-provisionnées avec des applications de streaming piraté (CRICFy, DooFlix, Sprozfy, RTS Tv, Flixoid, CyberFlix, Rapid Streamz, TvMob, HD/OceanStreams). L'infrastructure de contrôle utilise plusieurs domaines dont gmslb[.]net, safernetwork[.]io, tera-home[.]com et ninjatech[.]io. Le domaine ninjatech[.]io est la propriété de Moishi Kramer, VP R&D chez NetNut, dont le profil LinkedIn revendique la conception et la mise à l'échelle de l'architecture NetNut avant son acquisition par Alarum. En mai 2026, Qurium a subi une opération de scraping coûteux et disruptif provenant de plus de 1,4 million d'adresses IP. Ce modèle illustre la convergence entre botnets IoT grand public et fournisseurs de proxy résidentiels commercialisant ce trafic comme une infrastructure « légitime ».

---

### Recommandations

* Bloquer en bordure et en DNS les domaines C2 : gmslb[.]net, safernetwork[.]io, tera-home[.]com, ninjatech[.]io
* Segmenter le réseau d'entreprise pour isoler les appareils IoT/TV boxes et appliquer une politique default-deny
* Sensibiliser les collaborateurs aux risques des TV boxes Android non officielles vendues en ligne
* Surveiller les connexions chiffrées persistantes initiées par des appareils Android grand public
* Détecter le scraping massif provenant de pools d'IP résidentiels via corrélation ASN et entropie UA
* Participer aux efforts de takedown coordonnées (CERTs, Google, HUMAN Security) pour démanteler l'infrastructure

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les équipements Android TV (OTT/STB) connectés au réseau de l'entreprise et chez les employés en télétravail
* Segmenter le VLAN IoT/TV-box et appliquer une politique de default-deny vers les services internes sensibles
* Établir une baseline de trafic DNS et HTTP/HTTPS sortant pour détecter les communications vers les C2 de proxy résidentiel
* Sensibiliser les collaborateurs aux risques liés à l'achat de TV boxes non officielles (CRICFy, DooFlix, Sprozfy, etc.)
* Mettre en place des règles IDS/IPS détectant les tunnels chiffrés persistants initiés par des appareils IoT

#### Phase 2 — Détection et analyse

* Surveiller les requêtes DNS vers gmslb[.]net, safernetwork[.]io, tera-home[.]com et ninjatech[.]io
* Identifier les appareils Android émettant des connexions chiffrées longues vers un même FQDN (indicateur d'un C2 résidentiel)
* Détecter les volumes anormaux de trafic sortant depuis des TV boxes (proxy abuse)
* Repérer les patterns de scraping massif (>1,4 M d'adresses IP sources) ciblant les applications web hébergées
* Analyser les logs réseau à la recherche de tunnels applicatifs ouverts à la demande (SOCKS/HTTP over TLS)
* Alerter sur les comptes compromis via residential proxy (auth logs depuis des ASNs résidentiels atypiques)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les TV boxes identifiées comme compromis du réseau de l'entreprise
* Bloquer en bordure (proxy/DNS firewall) les domaines de C2 connus : gmslb[.]net, safernetwork[.]io, tera-home[.]com, ninjatech[.]io
* Révoquer les sessions actives des comptes potentiellement compromis via residential proxy
* Désactiver le port-forwarding et le NAT entrant sur les routeurs grand public hébergeant des TV boxes compromises
* Notifier les utilisateurs et bloquer les devices identifiés dans les flux d'account takeover
* Coordonner avec les FAI et les CERTs nationaux pour le takedown de l'infrastructure

#### Phase 4 — Activités post-incident

* Confirmer l'absence de compromission des systèmes internes exposés au LAN pendant la fenêtre d'infection
* Réaliser un forensic des TV boxes saisies : apps pré-installées, APK modifiés, persistances ADB
* Auditer les comptes utilisateurs et services ayant subi des tentatives de takeover durant la période
* Calculer l'impact financier des opérations de fraude publicitaire et de data-scraping subies
* Documenter les IOC et partager avec la communauté (MISP, OTX, abuse.ch)
* Renforcer la politique d'achat et d'utilisation de devices IoT au sein de l'organisation

#### Phase 5 — Threat Hunting (proactif)

* Chasser les devices Android (TV boxes, OTT, tablettes low-cost) présentant des APK signés par des certificats non-Google connus
* Rechercher dans le réseau les appareils établissant des tunnels TLS persistants non sollicités
* Monitorer les résolutions DNS vers les domaines historiquement liés à Vo1d/Badbox
* Identifier les ASN/IP résidentiels émettant du trafic de scraping coordonné depuis plus d'1 M d'adresses uniques
* Surveiller les marketplaces et dépôts d'apps pirates intégrant les frameworks Popa/Vo1d
* Établir des honeytokens exposés via des devices Android piégés pour détecter les recrutements botnet

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `gmslb[.]net` | High |
| DOMAIN | `safernetwork[.]io` | High |
| DOMAIN | `tera-home[.]com` | High |
| DOMAIN | `ninjatech[.]io` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1584.005** | Acquire Infrastructure : Botnet |
| **T1090** | Proxy |
| **T1090.001** | Proxy : Internal Proxy |
| **T1071.001** | Application Layer Protocol : Web Protocols |
| **T1571** | Non-Standard Port |
| **T1189** | Drive-by Compromise |
| **T1199** | Trusted Relationship |
| **T1606** | Forge Web Credentials |
| **T1114** | Email Collection |

---

### Sources

* [https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/](https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/)


---

<div id="tendances-de-threat-intelligence-juin-2026-clearfake-kali365-et-teampcp-dominent-le-paysage"></div>

## Tendances de threat intelligence juin 2026 : ClearFake, Kali365 et TeamPCP dominent le paysage

### Résumé technique

• ClearFake : drive-by JS → fake CAPTCHA → exécution PowerShell/cmd via paste-and-run
• Kali365 : PhaaS OAuth device code + AiTM → tokens Microsoft 365 volés (ex-GraphRunner)
• TeamPCP / Mini Shai-Hulud : ver npm/PyPI propagé via workflow CI TanStack compromis
• Exemples de commandes paste-and-run observées en mai 2026 : curl vers amber-22[.]com, iex vers ccudmcx[.]xyz, msIeXec vers hxxp://195[.]10[.]205[.]212/Cpcha, mshta sur PDF depuis 35613analytics[.]com
• Niveau de menace : High pour Microsoft 365 et supply-chain open-source

---

### Analyse de l'impact

Le rapport Red Canary de juin 2026 met en lumière la prédominance continue de ClearFake (n°1 pour le deuxième mois consécutif), un cluster utilisant du JavaScript injecté dans des sites compromis pour distribuer des malwares via drive-by download, souvent avec des leurres de faux CAPTCHA incitant l'utilisateur à copier-coller des commandes malveillantes (ClickFix / paste-and-run). Cette chaîne d'exécution apparaît dans 7 des 10 principales menaces du mois, dont ClearFake, MacSync Stealer, NetSupport Manager, ACR Stealer, Atomic Stealer, HijackLoader (retour depuis septembre 2025) et Scarlet Goldfinch. Kali365 fait ses débuts en 2e position : c'est une plateforme de phishing-as-a-service automatisant le device code phishing OAuth et les attaques AiTM contre Microsoft 365. TeamPCP refait surface avec la campagne « Mini Shai-Hulud », un ver auto-réplicant ciblant les écosystèmes npm et PyPI via un commit malveillant sur un workflow CI TanStack. Ces évolutions traduisent la convergence entre techniques d'ingénierie sociale de masse, exploitation des flux OAuth modernes et compromissions supply-chain dans les chaînes de développement open-source.

---

### Recommandations

* Bloquer en DNS/proxy : amber-22[.]com, ccudmcx[.]xyz, 35613analytics[.]com et l'IP 195[.]10[.]205[.]212
* Désactiver le device code flow OAuth sur Microsoft Entra ID ou le restreindre via Conditional Access
* Mettre en place une politique AppLocker/WDAC bloquant PowerShell/cmd non signés
* Auditer les dépendances npm/PyPI avec SBOM et activer le dependency confusion pinning
* Sensibiliser les utilisateurs aux techniques ClickFix (paste-and-run, faux CAPTCHA)
* Monitorer les commits sur les workflows CI critiques (TanStack, GitHub Actions) et alerter sur les auteurs inhabituels

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Durcir les endpoints avec blocage des scripts PowerShell/cmd non signés via AppLocker/WDAC
* Activer la protection renforcée contre le phishing OAuth et le device code flow sur Microsoft Entra ID
* Sensibiliser les utilisateurs aux techniques ClickFix / paste-and-run via des simulations régulières
* Restreindre l'usage de tokens Microsoft 365 aux sessions conformes à la Conditional Access
* Mettre en place une politique de code-signing et d'analyse SCA pour les dépendances npm/PyPI
* Cartographier les workflows CI/CD (TanStack, GitHub Actions, etc.) et isoler les secrets

#### Phase 2 — Détection et analyse

* Surveiller les connexions sortantes vers amber-22[.]com, ccudmcx[.]xyz, 35613analytics[.]com et l'IP 195[.]10[.]205[.]212
* Détecter les invocations de msIeXec[.]exe, PowerShell[.]exe et cmd[.]exe avec des commandes obfuscées (caractères ^)
* Identifier les flux de device code OAuth initiés par des utilisateurs non-Kali365 attendus
* Monitorer les activités Microsoft Graph anormales (reconnaissance, exfiltration de mails, création de règles inbox)
* Détecter les commits suspects sur les workflows CI (TanStack) et les packages npm/PyPI publiés de manière inattendue
* Rechercher les téléchargements de fichiers .pdf ou .lnk inhabituels depuis des URLs externes

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les tokens Microsoft 365 et sessions actives des comptes affectés par Kali365/AiTM
* Désactiver les device codes en cours et réinitialiser les enregistrements MFA
* Isoler les endpoints ayant exécuté des commandes paste-and-run et lancer un triage EDR
* Bloquer en DNS/proxy les domaines C2 identifiés (amber-22[.]com, ccudmcx[.]xyz, 35613analytics[.]com)
* Rollback des packages npm/PyPI compromis et invalidation des caches CI/CD
* Suspendre les workflows CI/CD infectés et régénérer les secrets/credentials exposés

#### Phase 4 — Activités post-incident

* Auditer l'intégrité des dépendances npm/PyPI et mettre en place du pinning + SBOM
* Analyser les boîtes mail des comptes compromis à la recherche de règles de transfert/forwarding créées
* Vérifier l'absence de persistance via scheduled tasks, services ou run keys ajoutées par HijackLoader
* Scanner les navigateurs à la recherche d'extensions ou de JavaScript injectés (ClearFake)
* Renforcer la politique d'application des mises-à-jour navigateur et bloquer les sites compromis
* Communiquer avec la communauté open-source si une dépendance compromise est identifiée

#### Phase 5 — Threat Hunting (proactif)

* Chasser les chaînes d'infection ClearFake dans les logs proxy/WAF (JS injecté + lures CAPTCHA)
* Monitorer l'apparition de nouveaux domaines paste-and-run (pattern ccudmcx[.]xyz)
* Identifier les activités GraphRunner/Kali365 via Microsoft 365 Unified Audit Logs
* Rechercher les commits Git anormaux sur les workflows CI (heures, auteurs, changements)
* Détecter les installations de packages npm/PyPI avec un maintainer récemment créé ou renommé
* Auditer les Conditional Access policies pour combler les bypass liés au device code flow

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `amber-22[.]com` | High |
| DOMAIN | `ccudmcx[.]xyz` | High |
| DOMAIN | `35613analytics[.]com` | High |
| IPV4 | `195[.]10[.]205[.]212` | High |
| URL | `hxxps://amber-22[.]com/api/metrics/run` | High |
| URL | `hxxp://195[.]10[.]205[.]212/Cpcha` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1189** | Drive-by Compromise |
| **T1059.001** | Command and Scripting Interpreter : PowerShell |
| **T1059.003** | Command and Scripting Interpreter : Windows Command Shell |
| **T1204.002** | User Execution : Malicious File |
| **T1027** | Obfuscated Files or Information |
| **T1556.006** | Modify Authentication Process : Multi-Factor Authentication |
| **T1528** | Steal Application Access Token |
| **T1078.004** | Valid Accounts : Cloud Accounts |
| **T1550.001** | Use Alternate Authentication Material : Application Access Token |
| **T1195.002** | Supply Chain Compromise : Compromise Software Supply Chain |
| **T1195.001** | Supply Chain Compromise : Compromise Software Dependencies |
| **T1053.005** | Scheduled Task/Job : Scheduled Task |
| **T1218.014** | System Binary Proxy Execution : MMC |
| **T1105** | Ingress Tool Transfer |

---

### Sources

* [https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)


---

<div id="art-004"></div>

## ART-004

### Résumé technique

_Non disponible._

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1u9s78c/](https://www.reddit.com/r/redteamsec/comments/1u9s78c/)


---

<div id="un-hacker-canadien-plaide-coupable-pour-une-cyberattaque-contre-un-site-republicain-du-texas"></div>

## Un hacker canadien plaide coupable pour une cyberattaque contre un site républicain du Texas

### Résumé technique

Cyberattaque contre une infrastructure web partisane, ayant conduit à l'ouverture de poursuites pénales et à un plaidoyer de culpabilité. Aucun IOC technique spécifique n'a été publié. L'attaque a probablement impliqué un accès non autorisé suivi d'éventuelles modifications de contenu ou exfiltration de données.

---

### Analyse de l'impact

Un ressortissant canadien a plaidé coupable de charges liées à une cyberattaque ciblant un site web affiliated au Parti républicain du Texas. L'affaire illustre la judiciarisation croissante des attaques informatiques à motivation politique, ainsi que la coopération entre autorités américaines et canadiennes. L'incident souligne la vulnérabilité persistante des infrastructures numériques d'organisations politiques, fréquemment ciblées par des acteurs isolés ou parrainés.

---

### Recommandations

* Renforcer l'authentification multifacteur sur tous les comptes administratifs des sites partisans.
* Effectuer des audits de sécurité réguliers du CMS et des extensions tierces.
* Mettre en place une veille active sur les fuites d'identifiants des collaborateurs politiques.
* Établir un plan de réponse aux incidents avec scénarios de défiguration et de compromission de données.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les partis politiques et administrateurs de sites aux attaques ciblées.
* Mettre en place une supervision WAF et durcir les CMS utilisés par les sites partisans.
* Établir des contacts préalables avec les forces de l'ordre (FBI, Gendarmerie royale du Canada) en cas d'incident transfrontalier.

#### Phase 2 — Détection et analyse

* Activer les alertes IDS/IPS et journaux WAF pour repérer toute activité anormale.
* Vérifier les indicateurs de défiguration ou modification non autorisée du contenu web.
* Collecter les logs d'accès et de modification pour analyse forensique.

#### Phase 3 — Confinement, éradication et récupération

* Isoler le serveur web compromis du reste de l'infrastructure.
* Restaurer le site à partir d'une sauvegarde intègre vérifiée.
* Préserver les preuves numériques (images disques, logs) en vue d'une coopération judiciaire.

#### Phase 4 — Activités post-incident

* Documenter l'incident et partager les IOC avec les partenaires sectoriels.
* Renforcer l'authentification et le durcissement du CMS.
* Participer à la coordination judiciaire transfrontalière (Entraide MLAT).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'accès administratifs anormaux sur les plateformes politiques alliées.
* Monitorer les fuites d'identifiants liés aux opérateurs partisans sur les forums cybercriminels.
* Cartographier les acteurs étatiques ou hacktivistes ciblant les institutions politiques nord-américaines.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Hameçonnage ou compromission initiale de site web à des fins politiques |
| **T1071** | Canal de commande et de contrôle application layer pour exfiltration ou défiguration |

---

### Sources

* [https://databreaches.net/2026/06/18/canadian-hacker-pleads-guilty-to-charges-for-cyberattack-on-texas-republican-website/](https://databreaches.net/2026/06/18/canadian-hacker-pleads-guilty-to-charges-for-cyberattack-on-texas-republican-website/)


---

<div id="le-hhs-ocr-regle-une-enquete-ransomware-contre-spencer-gifts-health-plan-pour-450-000-dollars-et-un-plan-daction-corrective"></div>

## Le HHS OCR règle une enquête ransomware contre Spencer Gifts Health Plan pour 450 000 dollars et un plan d'action corrective

### Résumé technique

Attaque par ransomware ayant entraîné une compromission de données PHI. Les détails techniques sur la souche employée ne sont pas publiés, mais le scénario typique implique un accès initial via hameçonnage ou VPN, suivi d'une élévation de privilèges et du déploiement d'un chiffreur. Les données exfiltrées avant chiffrement sont utilisées comme levier de double extorsion.

---

### Analyse de l'impact

Le Bureau des droits civils du Department of Health and Human Services a conclu un accord à 450 000 dollars avec Spencer Gifts Health Plan suite à une attaque par ransomware ayant compromis des données de santé protégées (PHI). L'accord impose un Corrective Action Plan contraignant. Cet épisode illustre la pression réglementaire croissante exercée par l'OCR sur les entités couvertes par la HIPAA et la nécessité d'une gouvernance rigoureuse des données de santé.

---

### Recommandations

* Revoir le programme de sécurité HIPAA et aligner les contrôles sur le NIST CSF 2.0.
* Tester la restauration des sauvegardes dans un environnement isolé.
* Mettre en place une segmentation réseau stricte entre les environnements RH/santé et le reste du SI.
* Documenter formellement le programme de gestion des risques et le plan de réponse HIPAA.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un registre à jour des actifs contenant des données PHI.
* Déployer une solution EDR/XDR avec supervision des comportements de chiffrement massif.
* Réaliser des sauvegardes immuables, testées régulièrement, isolées du domaine.
* Former le personnel à la détection des courriels d'hameçonnage initiaux.

#### Phase 2 — Détection et analyse

* Surveiller les alertes EDR liées à un volume anormal de chiffrement de fichiers.
* Activer les règles SIEM sur les comptes de service et l'élévation de privilèges.
* Vérifier les alertes d'exfiltration DNS et les connexions sortantes vers infrastructures suspectes.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes infectés du réseau.
* Désactiver les comptes compromis et révoquer les jetons d'authentification.
* Couper les partages réseau touchés et suspendre les sauvegardes en ligne pour éviter leur chiffrement.
* Notifier le HHS OCR dans les délais réglementaires.

#### Phase 4 — Activités post-incident

* Conduire une investigation forensique complète et produire un rapport HIPAA.
* Déposer une plainte auprès du FBI/IC3 et se coordonner avec les forces de l'ordre.
* Communiquer aux patients conformément aux obligations de notification.
* Auditer l'application du Corrective Action Plan (CAP) exigé par l'OCR.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs de persistance (T1053, T1543) sur l'ensemble du parc.
* Analyser les logs de messagerie pour identifier le vecteur initial d'intrusion.
* Cartographier les connexions réseau résiduelles vers des infrastructures de commande connues.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données à des fins d'extorsion |
| **T1083** | Reconnaissance système post-compromission |
| **T1059** | Exécution de commandes et de scripts sur les hôtes compromis |

---

### Sources

* [https://databreaches.net/2026/06/18/hhs-o%ef%ac%83ce-for-civil-rights-settles-ransomware-investigation-with-spencer-gifts-health-plan-for-450k-corrective-action-plan/](https://databreaches.net/2026/06/18/hhs-o%ef%ac%83ce-for-civil-rights-settles-ransomware-investigation-with-spencer-gifts-health-plan-for-450k-corrective-action-plan/)


---

<div id="royaume-uni-hcrg-notifie-enfin-les-patients-dune-attaque-ransomware-plus-dun-an-apres-lincident"></div>

## Royaume-Uni : HCRG notifie enfin les patients d'une attaque ransomware plus d'un an après l'incident

### Résumé technique

Attaque ransomware contre HCRG avec un délai de notification supérieur à un an, suggérant des difficultés de containment, d'investigation ou de cartographie des données impactées. Aucune famille de ransomware ni IOC n'ont été publiés. L'attaque illustre la problématique de la supply chain dans le secteur de la santé britannique.

---

### Analyse de l'impact

Plus d'un an après l'attaque ransomware, HCRG (fournisseur britannique de services de santé) notifie pour la première fois les patients impactés. Ce retard considérable soulève des interrogations sur les obligations de notification RGPD et sur la gouvernance de la réponse à incident. L'incident met en évidence les difficultés rencontrées par les acteurs de santé à contenir et qualifier une compromission à temps.

---

### Recommandations

* Imposer contractuellement des SLA stricts de notification aux sous-traitants.
* Évaluer en continu la conformité RGPD avec audits réguliers.
* Documenter la chaîne complète de traitement des données pour faciliter la notification.
* Renforcer la coordination entre RSSI internes et ceux des prestataires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place un contrat d'assurance cyber couvrant la notification et la gestion de crise.
* Préparer un modèle de notification conforme RGPD et ICO.
* Cartographier en amont les données patients hébergées chez les sous-traitants.
* Maintenir une cartographie à jour des prestataires tiers hébergeant des données sensibles.

#### Phase 2 — Détection et analyse

* Détecter les signes précoces de compromission via EDR et supervision des journaux VPN.
* Vérifier les alertes sur les services d'exfiltration (Mega, WeTransfer, services cloud).
* Activer les règles SIEM sur les comportements d'administration anormaux chez les prestataires.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les segments réseau touchés en coordination avec le prestataire.
* Suspendre les interconnexions avec les fournisseurs compromis.
* Préserver les preuves et journaux en vue de l'investigation.
* Notifier l'ICO dans les 72 heures conformément au RGPD si applicable.

#### Phase 4 — Activités post-incident

* Communiquer de manière transparente aux patients en détaillant les catégories de données exposées.
* Réaliser une analyse post-mortem conjointe avec le prestataire.
* Renforcer les clauses contractuelles de sécurité et audit chez les sous-traitants.
* Suivre les obligations de reporting de l'ICO et du NHS.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des IOC issus de l'attaque dans l'ensemble du SI et des partenaires.
* Cartographier les chemins de latéralité potentielle depuis le prestataire.
* Surveiller la réutilisation d'identifiants exposés sur d'autres plateformes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données sensibles |
| **T1567** | Exfiltration de données via service de transfert ou cloud |
| **T1657** | Extorsion financière liée à la menace de divulgation |

---

### Sources

* [https://databreaches.net/2026/06/18/uk-more-than-one-year-later-hcrg-is-first-notifying-patients-of-ransomware-attack/](https://databreaches.net/2026/06/18/uk-more-than-one-year-later-hcrg-is-first-notifying-patients-of-ransomware-attack/)


---

<div id="nintendo-vise-par-une-demande-de-rancon-de-2-millions-de-dollars-du-groupe-shadowbytes"></div>

## Nintendo visé par une demande de rançon de 2 millions de dollars du groupe ShadowBytes

### Résumé technique

Revendication de compromission par un nouveau groupe se nommant ShadowBytes, accompagnée d'une demande de rançon. Aucun détail technique (vecteur initial, IOC, volume de données) n'a été diffusé publiquement. Le schéma typique combine double extorsion (chiffrement + menace de divulgation) et pression sur la réputation.

---

### Analyse de l'impact

Le groupe se présentant sous le nom de ShadowBytes réclame 2 millions de dollars à Nintendo pour une prétendue compromission. Ce type d'incident illustre le ciblage croissant des grands éditeurs de jeux vidéo, dont les données clients (comptes, paiements) et la propriété intellectuelle sont très valorisées. La crédibilité de la revendication reste à confirmer, plusieurs groupes usurpant des marques existantes pour accroître leur pression.

---

### Recommandations

* Vérifier en interne la réalité de la compromission via la chasse aux IOC connus.
* Activer une cellule de gestion de crise cyber et une communication maîtrisée.
* Coordonner avec les autorités (FBI, NCSC) avant toute négociation.
* Évaluer l'impact potentiel sur les comptes utilisateurs et renforcer la détection de prises de contrôle.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Segmenter strictement les réseaux de développement des environnements bureautiques.
* Maintenir des sauvegardes immuables et isolées pour les actifs critiques (code source, données utilisateurs).
* Surveiller les communications avec les groupes d'extorsion émergents sur les darknets.
* Former les équipes aux techniques d'ingénierie sociale ciblant le secteur gaming.

#### Phase 2 — Détection et analyse

* Surveiller les traces d'exfiltration massive via DLP et journaux proxy.
* Activer les alertes SIEM sur les connexions sortantes vers des services de partage de fichiers.
* Mettre en place une veille des fuites revendiquées par les groupes ransomware.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les serveurs compromis et couper les partages réseau.
* Désactiver les comptes et clés d'API potentiellement exposés.
* Préserver toutes les preuves (mémoire, disques, journaux) avant toute remédiation.
* Engager un conseil juridique spécialisé en négociation ransomware et obligations de divulgation.

#### Phase 4 — Activités post-incident

* Décider de la stratégie de paiement conformément aux recommandations des forces de l'ordre.
* Communiquer de manière proactive aux clients et partenaires si des données ont fuité.
* Renforcer l'authentification (MFA) et l'application du moindre privilège.
* Mener une revue post-incident et mettre à jour le plan de réponse.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les IOC liés à ShadowBytes dans les logs de proxy et DNS.
* Rechercher les artefacts de l'intrusion initiale (web shell, binaire signé).
* Surveiller les références à Nintendo sur les forums cybercriminels et marchés de données.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données à des fins d'extorsion |
| **T1657** | Extorsion financière |
| **T1567** | Exfiltration de données vers infrastructure externe |

---

### Sources

* [https://gamesbriefly.news/nintendo-gets-hit-with-a-2-million-ransom-demand-and-the-final-boss-is-a-group-c](https://gamesbriefly.news/nintendo-gets-hit-with-a-2-million-ransom-demand-and-the-final-boss-is-a-group-c)


---

<div id="un-echantillon-malveillant-passe-inapercu-pour-la-plupart-des-editeurs-av-seuls-rise-et-malwarebytes-le-detectent"></div>

## Un échantillon malveillant passe inaperçu pour la plupart des éditeurs AV, seuls Rise et MalwareBytes le détectent

### Résumé technique

Binaire malveillant avec dépendances lourdes, difficilement détecté par la majorité des moteurs AV statiques. La détection sandbox a échoué probablement à cause de la complexité d'environnement requise pour l'exécution. Le taux de détection très faible en fait un candidat plausible pour des opérations ciblées.

---

### Analyse de l'impact

Un chercheur de vx-underground rapporte un échantillon malveillant resté largement indétecté par les solutions antivirus grand public. Seuls Rise et MalwareBytes ont émis une alerte via analyse statique. La lourdeur de l'échantillon et ses nombreuses dépendances ont compliqué la détection sandbox. L'épisode rappelle l'écart de maturité entre éditeurs et la nécessité d'une approche multi-couches (EDR, XDR, analyse comportementale).

---

### Recommandations

* Combiner plusieurs moteurs de détection (statique, dynamique, comportementale).
* Renforcer les capacités internes d'analyse malware et de rétro-ingénierie.
* Sensibiliser les analystes à la chasse basée sur les comportements et non uniquement sur les signatures.
* Participer activement au partage d'IOC communautaires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* S'entraîner à analyser des échantillons malveillants dans des environnements isolés et instrumentés.
* Maintenir plusieurs moteurs AV/EDR pour évaluer la couverture multi-fournisseurs.
* Disposer d'images VM « sales » pour l'exécution contrôlée.
* Développer des playbooks internes d'analyse dynamique.

#### Phase 2 — Détection et analyse

* Ingérer les échantillons dans un sandbox multi-moteurs pour évaluer la détection.
* Comparer la couverture entre éditeurs (Rise, MalwareBytes, etc.).
* Collecter les indicateurs comportementaux lors de l'exécution contrôlée.

#### Phase 3 — Confinement, éradication et récupération

* Stocker les échantillons dans une bibliothèque sécurisée et journalisée.
* Restreindre l'accès aux analystes habilités.
* Désactiver les canaux de diffusion identifiés et bloquer les IOC associés.

#### Phase 4 — Activités post-incident

* Partager les IOC et YARA rules avec la communauté (vx-underground, MISP).
* Documenter les méthodes d'évasion observées.
* Améliorer les signatures internes sur la base des indicateurs collectés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs les signatures comportementales des techniques d'évasion.
* Cartographier les familles d'échantillons non détectés par la majorité des éditeurs.
* Surveiller les nouveaux posts de vx-underground pour anticiper les vagues d'attaque.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1027** | Code obfusqué et dépendances excessives pour échapper à l'analyse |
| **T1059** | Exécution de scripts malveillants |
| **T1497** | Détection de sandbox et virtualisation |

---

### Sources

* [https://t.me/vxunderground/8971](https://t.me/vxunderground/8971)


---

<div id="un-malware-slop-ia-distribue-via-discord-desassemble-en-quelques-secondes"></div>

## Un malware « slop IA » distribué via Discord désassemblé en quelques secondes

### Résumé technique

Malware basé sur Electron JS, facilement décompilable, avec présence de commentaires générés par IA. Distribué via Discord (mécanisme typique de social engineering). Le caractère « slop » suggère un volume important, une qualité variable et des vulnérabilités introduites involontairement par l'auteur humain ou le modèle.

---

### Analyse de l'impact

Un chercheur a reçu et analysé un binaire malveillant transmis via Discord, rapidement identifié comme un malware « slop » généré par IA à partir d'Electron JS. L'échantillon contenait des marqueurs typiques d'un code rédigé par des modèles LLM, facilitant la rétro-ingénierie. Cette tendance illustre l'industrialisation de la production de malware par IA, augmentant le volume mais pas nécessairement la sophistication.

---

### Recommandations

* Filtrer ou alerter sur les exécutables reçus via Discord et autres messageries grand public.
* Renforcer la chasse basée sur les signatures de frameworks JS malveillants.
* Surveiller la diffusion de binaires générés par IA et adapter la détection comportementale.
* Éduquer les communautés Discord à ne pas exécuter de binaires non vérifiés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs Discord au risque de fichiers et exécutables inconnus.
* Activer la protection en temps réel des terminaux et bloquer l'exécution par défaut depuis Discord.
* Maintenir une liste de signatures Electron malveillantes connues.
* Encourager l'utilisation de canaux officiels pour la distribution de logiciels.

#### Phase 2 — Détection et analyse

* Détecter via EDR les signatures de processus Electron anormaux.
* Surveiller les téléchargements depuis Discord sur les postes utilisateurs.
* Vérifier les alertes sur les fichiers générés par IA (marqueurs de modèles LLM).

#### Phase 3 — Confinement, éradication et récupération

* Mettre en quarantaine le fichier malveillant et bloquer le hash sur l'ensemble du parc.
* Isoler les postes ayant exécuté le binaire.
* Analyser les comptes Discord potentiellement compromis et révoquer les jetons.

#### Phase 4 — Activités post-incident

* Notifier les utilisateurs ayant potentiellement reçu le fichier.
* Publier une alerte sur les canaux Discord internes.
* Sensibiliser à nouveau les communautés ciblées et vérifier les configurations anti-spam Discord.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les hashs et signatures d'outils malveillants basés sur Electron JS dans le SI.
* Cartographier les canaux Discord fréquentés par les collaborateurs.
* Surveiller les campagnes de « malware slop » généré par IA sur les forums cybercriminels.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1204** | Exécution par l'utilisateur d'un binaire reçu via messagerie |
| **T1059** | Exécution de scripts via application Electron |
| **T1027** | Code facilement décompilable et présence de marqueurs IA |

---

### Sources

* [https://t.me/vxunderground/8970](https://t.me/vxunderground/8970)


---

<div id="dashlane-revele-un-brute-force-ciblant-le-flux-denregistrement-dappareils-moins-de-20-coffres-chiffres-exposes"></div>

## Dashlane révèle un brute-force ciblant le flux d'enregistrement d'appareils, moins de 20 coffres chiffrés exposés

### Résumé technique

Attaque par force brute sur la procédure d'enregistrement de nouveaux appareils Dashlane. Les coffres concernés restent chiffrés avec Argon2 (dérivation) et AES-256-CBC HMAC-SHA256 (chiffrement symétrique et intégrité). L'absence de fuite des mots de passe maîtres limite fortement la portée de la compromission. Dashlane a ajouté des protections supplémentaires sur le flux d'enregistrement.

---

### Analyse de l'impact

Le gestionnaire de mots de passe Dashlane a subi une attaque par brute-force ciblant son flux d'enregistrement de nouveaux appareils. Moins de 20 utilisateurs ont vu leurs coffres chiffrés exposés, sans que les mots de passe maîtres ne soient compromis. Dashlane a renforcé les protections sur ce flux. L'incident souligne la surface d'attaque résiduelle même sur des produits de sécurité, et l'importance des mécanismes cryptographiques solides (Argon2, AES-256) pour limiter l'impact.

---

### Recommandations

* Activer la MFA sur tous les comptes Dashlane et autres gestionnaires de mots de passe.
* Surveiller les notifications d'enregistrement de nouvel appareil et signaler toute activité suspecte.
* Utiliser des mots de passe maîtres robustes et uniques.
* Vérifier la résistance cryptographique des solutions de gestion d'identifiants déployées en entreprise.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Surveiller en continu les tentatives d'authentification inhabituelles.
* Éduquer les utilisateurs à l'activation de la MFA sur leurs comptes sensibles.
* Limiter le débit des tentatives d'enregistrement d'appareils et durcir les contrôles.
* Auditer régulièrement la résistance des coffres chiffrés aux attaques hors-ligne.

#### Phase 2 — Détection et analyse

* Activer des alertes en temps réel sur les rafales de tentatives d'enregistrement d'appareils.
* Détecter les sessions réussies depuis des appareils nouvellement enregistrés.
* Comparer les empreintes IP, géolocalisation et user-agent lors de l'enregistrement.

#### Phase 3 — Confinement, éradication et récupération

* Désactiver les sessions associées à un appareil nouvellement enregistré frauduleusement.
* Forcer la rotation des mots de passe maîtres pour les comptes identifiés comme à risque.
* Renforcer le flux d'enregistrement (captcha adaptatif, friction supplémentaire, MFA obligatoire).
* Informer les moins de 20 utilisateurs concernés et les accompagner.

#### Phase 4 — Activités post-incident

* Publier un avis de sécurité transparent et préciser les mesures prises.
* Évaluer la résistance cryptographique (Argon2, AES-256-CBC HMAC-SHA256) des coffres affectés.
* Améliorer la défense en profondeur sur le flux d'enregistrement.
* Coordonner avec les CERTs et partenaires de partage d'IOC.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les IOC IP/ASN associés aux attaques sur l'ensemble de l'infrastructure.
* Chasser des tentatives d'enregistrement frauduleuses similaires sur d'autres services.
* Surveiller les marchés de données pour la revente de coffres chiffrés Dashlane.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1110** | Brute-force sur le flux d'enregistrement de nouvel appareil |
| **T1078** | Abus de comptes valides via authentification compromise |
| **T1555** | Accès à des bases de données d'identifiants stockées |

---

### Sources

* [https://www.pcmag.com/news/password-manager-dashlane-reveals-how-a-hacker-stole-encrypted-vaults](https://www.pcmag.com/news/password-manager-dashlane-reveals-how-a-hacker-stole-encrypted-vaults)


---

<div id="accord-a-plusieurs-millions-de-dollars-conclu-suite-a-la-cyberattaque-lockbit-contre-mcna-dental-ayant-touche-pres-de-9-millions-de-personnes-dont-des-enfants"></div>

## Accord à plusieurs millions de dollars conclu suite à la cyberattaque LockBit contre MCNA Dental ayant touché près de 9 millions de personnes, dont des enfants

### Résumé technique

Attaque par ransomware LockBit contre MCNA Dental en 2023, avec compromission de données personnelles et médicales sensibles d'environ 9 millions de patients, dont des enfants. LockBit est connu pour son modèle RaaS (Ransomware-as-a-Service), l'utilisation de double extorsion et la publication de données sur son site de fuite. La récupération post-incident inclut un règlement financier et probablement un programme de notification et de surveillance des victimes mineures.

---

### Analyse de l'impact

Un accord financier à plusieurs millions de dollars a été conclu suite à l'attaque ransomware LockBit de 2023 contre MCNA Dental, qui avait compromis les données de près de 9 millions de personnes, dont de nombreux mineurs. L'affaire souligne la sévérité réglementaire post-incident dans le secteur de la santé et les risques accrus liés à la protection des données pédiatriques. LockBit continue d'être l'une des principales menaces pour les organismes de santé nord-américains.

---

### Recommandations

* Renforcer la sécurité des dossiers dentaires et pédiatriques (chiffrement, contrôle d'accès).
* Mettre en place une veille spécifique sur LockBit et ses variantes (LockBit 3.0, 4.0).
* Coordonner avec HHS OCR sur les obligations HIPAA spécifiques aux données de mineurs.
* Déployer un programme de monitoring des identités pour les victimes exposées.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier l'ensemble des PHI et données personnelles sensibles stockées.
* Déployer une surveillance spécifique des indicateurs LockBit (IOC, YARA).
* Vérifier la segmentation réseau et l'isolation des sauvegardes.
* Sensibiliser les équipes dentaires et administratives à la menace ransomware.

#### Phase 2 — Détection et analyse

* Activer les règles SIEM/EDR sur les comportements caractéristiques de LockBit.
* Surveiller les alertes sur les exécutables LockBit (loader, modules d'escalade).
* Détecter les communications sortantes vers les infrastructures de fuite de LockBit.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes infectés et désactiver les comptes compromis.
* Préserver les preuves pour les forces de l'ordre et auditeurs externes.
* Notifier les autorités compétentes (FBI, HHS OCR) et les avocats spécialisés.
* Couper les sauvegardes en ligne pour éviter le chiffrement.

#### Phase 4 — Activités post-incident

* Coopérer avec les forces de l'ordre et partager les IOC.
* Communiquer de manière proactive aux patients, y compris les mineurs.
* Participer au processus de règlement HIPAA et appliquer le CAP.
* Mener une revue post-incident et mettre à jour le plan de réponse.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les artefacts LockBit (services, tâches planifiées, payloads) sur l'ensemble du parc.
* Rechercher les IOC de LockBit 3.0/4.0 dans les logs d'authentification.
* Surveiller les forums de revente de données issues de MCNA et d'autres acteurs dentaires.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données via ransomware LockBit |
| **T1657** | Double extorsion avec menace de divulgation publique |
| **T1078** | Accès initial via comptes compromis |

---

### Sources

* [https://www.healthcareinfosecurity.com/](https://www.healthcareinfosecurity.com/)
