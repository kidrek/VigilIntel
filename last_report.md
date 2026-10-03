# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Vulnérabilités de produits du secteur santé : Retour d'expérience du CERT Santé et du CERT-FR (02 octobre 2026)](#vulnerabilites-de-produits-du-secteur-sante-retour-dexperience-du-cert-sante-et-du-cert-fr-02-octobre-2026)
  * [Mises à jour des règles de détection SigmaHQ : création de processus enfant inhabituelle, autorisations d'abonnement Azure, exécution de schtasks renommée, demandes de tickets Kerberos suspectes, abus de WSL et archivage des références de règles](#mises-a-jour-des-regles-de-detection-sigmahq-creation-de-processus-enfant-inhabituelle-autorisations-dabonnement-azure-execution-de-schtasks-renommee-demandes-de-tickets-kerberos-suspectes-abus-de-wsl-et-archivage-des-references-de-regles)
  * [Fusionner la PR #6355 de @redsand - Ajouter un filtre pour le TLD microsoft légitime](#fusionner-la-pr-6355-de-redsand-ajouter-un-filtre-pour-le-tld-microsoft-legitime)
  * [Paessolucoes Par panzer](#paessolucoes-par-panzer)
  * [Contexte long — la clôture:1. Rechercher dans la page BUILT les clés secrètes (publiable ok ; clé de service : supprimer, redéployer, faire tourner, traiter comme exposée). 2. Chaque table : confirmer que la règle de ligne existe, puis le prouver avec un second compte de test et sans session, en lecture et en écriture. 3. Chaque validation obtient une ligne Comment-vérifié, une date et un humain nommé.Vos propres applications uniquement. Pas un test d'intrusion — les questions que personne n'a posées.#AppSec #infosec](#contexte-long-la-cloture1-rechercher-dans-la-page-built-les-cles-secretes-publiable-ok-cle-de-service-supprimer-redeployer-faire-tourner-traiter-comme-exposee-2-chaque-table-confirmer-que-la-regle-de-ligne-existe-puis-le-prouver-avec-un-second-compte-de-test-et-sans-session-en-lecture-et-en-ecriture-3-chaque-validation-obtient-une-ligne-comment-verifie-une-date-et-un-humain-nommevos-propres-applications-uniquement-pas-un-test-dintrusion-les-questions-que-personne-na-poseesappsec-infosec)
  * [#infosec #malware #antivirusBlog elhacker.NET: Usan exclusiones de Microsoft Defender para ocultar malwarehttps://blog.elhacker.net/2026/10/usan-exclusiones-de-microsoft-defender.html?m=1](#infosec-malware-antivirusblog-elhackernet-usan-exclusiones-de-microsoft-defender-para-ocultar-malwarehttpsblogelhackernet202610usan-exclusiones-de-microsoft-defenderhtmlm1)
  * [Les frappes iraniennes sur les centres de données d'Amazon ont causé une perte permanente de données clients](#les-frappes-iraniennes-sur-les-centres-de-donnees-damazon-ont-cause-une-perte-permanente-de-donnees-clients)
  * [Possible Phishing 🎣  on: ⚠️hxxps[:]//www[.]roblox[.]com[.]am/users/474624665347/profile  🧬 Analysis at: https://urldna.io/scan/6abf64bd3b77500002f12ce9 #cybersecurity #phishing #infosec #urldna #scam #infosec](#possible-phishing-on-hxxpswwwrobloxcomamusers474624665347profile-analysis-at-httpsurldnaioscan6abf64bd3b77500002f12ce9-cybersecurity-phishing-infosec-urldna-scam-infosec)
  * [170.64.214.68 flagged for mixed malicious activity. Hosted at DigitalOcean in AU, tracked by 2 independent feeds. Worth a look if it hits your logs. https://www.valtersit.com/threat-ip/170.64.214.68/ #ThreatIntel #InfoSec](#1706421468-flagged-for-mixed-malicious-activity-hosted-at-digitalocean-in-au-tracked-by-2-independent-feeds-worth-a-look-if-it-hits-your-logs-httpswwwvaltersitcomthreat-ip1706421468-threatintel-infosec)
  * [Mat Bao Corporation Par rhysida](#mat-bao-corporation-par-rhysida)
  * [Thai Lion Air Par qilin](#thai-lion-air-par-qilin)
  * [La ville de Vicksburg, Mississippi, éteint ses ordinateurs après une cyberattaque](#la-ville-de-vicksburg-mississippi-eteint-ses-ordinateurs-apres-une-cyberattaque)
  * [Plus de 543 000 identifiants valides exposés dans des dépôts #GitHub publiqueshttps://www.bleepingcomputer.com/news/security/over-543-000-valid-credentials-exposed-in-public-github-repositories/#cybersecurity #DataBreach](#plus-de-543-000-identifiants-valides-exposes-dans-des-depots-github-publiqueshttpswwwbleepingcomputercomnewssecurityover-543-000-valid-credentials-exposed-in-public-github-repositoriescybersecurity-databreach)
  * [Des domaines de remplacement utilisés par 349 compétences d'agents IA détectés redirigeant vers des arnaques](#des-domaines-de-remplacement-utilises-par-349-competences-dagents-ia-detectes-redirigeant-vers-des-arnaques)
  * [Cyber Brief 26-10 - September 2026](#cyber-brief-26-10-september-2026)
  * [La CISA et le FBI avertissent les opérateurs OT des piratages de tiers](#la-cisa-et-le-fbi-avertissent-les-operateurs-ot-des-piratages-de-tiers)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La production du jour est massivement dominée par les vulnérabilités (59 entrées) et les fuites de données (17), signe d'une journée à forte composante tactique et opérationnelle plutôt que stratégique. Le volume de vulnérabilités, près de quatre fois supérieur à celui des articles (16), suggère une vague de divulgations coordonnées ou de correctifs critiques nécessitant une priorisation rapide par les équipes de gestion des correctifs. Les 17 violations de données confirment une pression continue sur les chaînes d'approvisionnement et les tiers, avec un risque réputationnel et réglementaire immédiat. À l'inverse, la faible activité sur les acteurs de la menace (3), la géopolitique (2) et la réglementation (3) ne doit pas être interprétée comme un apaisement : elle reflète probablement un décalage de publication ou une couverture médiatique concentrée sur l'exploitation. La priorité du jour doit donc porter sur la réduction de la surface d'exposition, la vérification des correctifs et la surveillance des fuites concernant nos données et celles de nos partenaires. Nous recommandons de croiser les vulnérabilités publiées avec les actifs exposés et de déclencher une revue des accès tiers dans les 24 à 48 heures. Enfin, maintenir une veille sur les acteurs étatiques et les évolutions réglementaires reste essentiel pour anticiper les prochaines vagues, malgré leur faible volume aujourd'hui.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Booba Project** | education, higher-education | Chiffrement, exfiltration, extorsion, accès via identifiants valides. | T1486, T1567, T1078, T1657 | [https://www.yazoul.net/intel/claim/2026-10-02-university-of-illinois-chicago-ransomware-claim-by-booba-project-oct-2026](https://www.yazoul.net/intel/claim/2026-10-02-university-of-illinois-chicago-ransomware-claim-by-booba-project-oct-2026)<br>[https://mastodon.social/@Matchbook3469/117373194540354654](https://mastodon.social/@Matchbook3469/117373194540354654) |
| **ShinyHunters** | government, healthcare, pharma, public sector | Exploitation de vulnérabilités, identifiants compromis, phishing, exfiltration, extorsion, parfois ransomware via affiliés. | T1190, T1078, T1566, T1567, T1657, T1114, T1213, T1496, T1409, T1486 | [https://opensourcemalware.com/blog/the-opensourcemalwareshow-episode23](https://opensourcemalware.com/blog/the-opensourcemalwareshow-episode23)<br>[https://www.npr.org/2026/09/30/nx-s1-5985084/fbi-investigating-massive-data-breach-of-the-bureaus-job-portal](https://www.npr.org/2026/09/30/nx-s1-5985084/fbi-investigating-massive-data-breach-of-the-bureaus-job-portal)<br>[https://infosec.exchange/@security_crawler_carl/117372616469919819](https://infosec.exchange/@security_crawler_carl/117372616469919819)<br>[https://infosec.exchange/@XposedOrNot/117371668282295512](https://infosec.exchange/@XposedOrNot/117371668282295512)<br>[https://cert.europa.eu/publications/threat-intelligence/cb26-10/](https://cert.europa.eu/publications/threat-intelligence/cb26-10/) |
| **Scattered Spider (alias : Muddled Libra)** | multi-secteurs | Évasion de Microsoft Defender via exclusions, PowerShell, WMI, GPO. | T1562.001, T1059.001, T1047, T1112, T1484.001 | [https://blog.elhacker.net/2026/10/usan-exclusiones-de-microsoft-defender.html?m=1](https://blog.elhacker.net/2026/10/usan-exclusiones-de-microsoft-defender.html?m=1) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Europe, Mondial** | Sécurité civile, environnement, infrastructures critiques | Incendies de forêt comme nouvelle vulnérabilité stratégique | Les incendies de forêt ne relèvent plus uniquement de la protection des massifs forestiers. L’extension géographique du risque, l’allongement des saisons à risque et la possibilité d’incendies majeurs simultanés sur plusieurs territoires transforment ce phénomène en enjeu de sécurité nationale. Il met à l’épreuve la capacité des États à protéger les populations, les infrastructures critiques et les fonctions essentielles. Cette évolution souligne l’interconnexion entre changement climatique, résilience des territoires et planification stratégique. | [https://www.iris-france.org/les-incendies-de-foret-revelateurs-dune-nouvelle-vulnerabilite-strategique/](https://www.iris-france.org/les-incendies-de-foret-revelateurs-dune-nouvelle-vulnerabilite-strategique/) |
| **Europe, États-Unis, International** | Diplomatie, justice internationale, droits humains | Pression américaine contre la CPI et réaction européenne timorée | L’administration Trump intensifie ses tentatives de déstabilisation de la Cour pénale internationale, notamment par des sanctions contre des magistrats et des appels aux États parties pour qu’ils se retirent du statut de Rome. Cette offensive s’inscrit dans un contexte d’enquêtes de la CPI visant des intérêts américains en Afghanistan et la situation en Palestine, avec un mandat d’arrêt contre Benyamin Netanyahou en novembre 2024. La réaction européenne apparaît limitée face à une attaque contre une institution centrale du droit international, ce qui pose la question de la capacité de l’Europe à défendre l’ordre juridique multilatéral. | [https://www.iris-france.org/trump-cpi-la-reaction-timoree-des-europeens/](https://www.iris-france.org/trump-cpi-la-reaction-timoree-des-europeens/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| AI-GOV-2026-10 | GuidePoint Security (éditeur privé, analyse de gouvernance) ; US Court of Appeals for the District of Columbia Circuit et US Department of Defense (affaire Anthropic) | 2026-10-02 | États-Unis (DC Circuit, DoD) ; portée internationale pour les bonnes pratiques de gouvernance IA | AI-GOV-2026-10 | Deux angles complémentaires du même sujet : la gouvernance de l'IA et le statut juridique des garde-fous des modèles. D'un côté, l'article de GuidePoint Security décrit l'adoption « bottom-up » de l'IA générative par les employés (Shadow AI) qui précède et dépasse les politiques de gouvernance construites « top-down ». Le problème central n'est pas tant l'usage non autorisé que l'absence de visibilité : quelles données sont saisies dans les outils, quelles applications accèdent aux données d'entreprise, où vont ces données, combien de temps sont-elles conservées, quelles sorties IA alimentent des décisions métier et qui est responsable en cas de résultat inattendu. Une politique ne peut pas couvrir ce que l'organisation ignore. Les recherches du FAIR Institute citées indiquent que 80 % des organisations utilisent ou expérimentent l'IA dans leurs programmes de risque cyber, dont 43 % en phase d'expérimentation — précisément la phase où la gouvernance est la moins mature. De l'autre côté, la décision 2-1 du DC Circuit valide le blacklisting d'Anthropic par le Pentagone au titre du Federal Acquisition Supply Chain Security Act : le fait qu'Anthropic ait entraîné Claude à refuser certaines tâches (surveillance de masse, guerre létale autonome) suffit à qualifier l'entreprise de « risque pour la chaîne d'approvisionnement », la définition légale reposant sur ce que fait l'entreprise et non sur ses intentions. Cette décision crée un conflit bicôtier avec la décision californienne favorable à Anthropic sur le terrain du Premier Amendement, et soulève une question systémique : les entreprises d'IA pourraient hésiter à intégrer des garde-fous dans leurs modèles si ceux-ci deviennent un motif d'exclusion des marchés publics. Les deux textes convergent sur un point : la gouvernance de l'IA (interne comme contractuelle) doit être explicite, documentée et opposable, car les choix techniques (garde-fous, outils autorisés, rails de données) ont désormais des conséquences juridiques et commerciales directes. | [https://www.guidepointsecurity.com/blog/ai-governance-prompt-to-policy/](https://www.guidepointsecurity.com/blog/ai-governance-prompt-to-policy/)<br>[https://www.bankinfosecurity.com/us-appeals-court-backs-pentagon-blacklisting-anthropic-a-32941](https://www.bankinfosecurity.com/us-appeals-court-backs-pentagon-blacklisting-anthropic-a-32941) |
| AWS-NFW-RULEHIT-2026 | Amazon Web Services (AWS) ; cadres de conformité PCI DSS 4.0 et Digital Operational Resilience Act (DORA) | 2026-10-02 | International (toutes les régions AWS supportant Network Firewall, hors Moyen-Orient : Émirats arabes unis et Bahreïn) ; exigences européennes via DORA | AWS-NFW-RULEHIT-2026 | AWS Network Firewall active par défaut, sans surcoût, le comptage des correspondances (rule hit counts) pour les règles stateful, dans les groupes de règles personnalisés et managés (les règles stateless ne sont pas couvertes). Le compteur s'incrémente lorsqu'une correspondance génère un journal d'alerte : les actions alert, drop et reject produisent ces journaux automatiquement, tandis que les règles en action pass doivent inclure le mot-clé alert. AWS ajoute des métadonnées de groupe de règles aux journaux d'alerte, exploitées par le tableau de bord Network Firewall (vue Top Rule Hits : règles les plus déclenchées, part de l'activité, détails, dernière occurrence) et interrogeables via CloudWatch Logs Insights ou Amazon Athena. L'enjeu est directement réglementaire : les organisations dont les politiques de gouvernance imposent la suppression des règles dormantes après une période définie n'avaient jusqu'ici aucun mécanisme pour les identifier, et les équipes en charge de PCI DSS 4.0 ou de DORA peinaient à prouver que des contrôles spécifiques fonctionnent réellement. La fonctionnalité sert aussi la réponse à incident : filtrer les compteurs sur la fenêtre temporelle d'un incident suspecté (par exemple une règle détectant du trafic vers un domaine OAST, indice d'exfiltration ou de validation de vulnérabilité) évite l'analyse manuelle de milliers d'entrées de journal. Des règles dont les identifiants de signature n'apparaissent pas dans la métrique n'ont pas correspondu au trafic sur la période, ce qui peut signaler une règle obsolète ou mal ordonnée. | [https://www.helpnetsecurity.com/2026/08/24/aws-network-firewall-rule-hit-count-capability/](https://www.helpnetsecurity.com/2026/08/24/aws-network-firewall-rule-hit-count-capability/) |
| EU-AGENTIC-FINANCE-2026 | Circle (réseau Arc) ; Eurosysteme / Banque centrale européenne (Pontes) ; participants bancaires (Société Générale, Deutsche Bank, Santander, Banque européenne d'investissement) | 2026-10-02 | Union européenne (Eurosystème, TARGET) et international (infrastructure privée Arc, USDC) | EU-AGENTIC-FINANCE-2026 | Sur le réseau Cloudflare, qui transporte environ un cinquième du trafic mondial, les requêtes automatisées ont dépassé celles des humains au printemps 2026 : les agents logiciels savent chercher, comparer, déclencher des actions et désormais payer. C'est la « finance agentique » — des logiciels autonomes dotés d'un portefeuille, d'un mandat et de règles de dépense — qui pose une question stratégique : dans quelle monnaie paieront les agents IA ? Deux infrastructures lancées à cinq jours d'intervalle incarnent la bataille. Le 16 septembre, Circle a ouvert Arc, blockchain dédiée aux usages financiers et à l'économie agentique, avec BlackRock, Visa, Mastercard, ICE et la DTCC parmi les validateurs fondateurs, complétée par un « Agent Stack » équipant un logiciel autonome d'un portefeuille et de droits de dépense. Circle revendique 98,8 % du volume des transactions pilotées par des agents, mais les volumes restent modestes (8,87 millions de paiements pour 940 000 dollars en mai 2026) : la bataille se joue donc maintenant, au moment où les développeurs choisissent interfaces et bibliothèques, car ces choix deviennent difficiles à déloger une fois intégrés au code. Le 21 septembre, l'Eurosystème a lancé Pontes, qui ne crée pas de nouvelle monnaie mais permet aux banques et marchés sur registres distribués de régler en monnaie de banque centrale ; treize participants ont rejoint le dispositif et la BCE a annoncé des travaux préparatoires pour investir une partie de ses fonds propres dans des titres tokenisés réglés via Pontes. Le risque pour l'Europe n'est pas une décision explicite en faveur du dollar : il s'opère discrètement quand un développeur intègre une bibliothèque, qu'une entreprise choisit une interface de paiement ou qu'un agent recherche le rail de règlement disponible — un logiciel ne choisit pas par patriotisme, il choisit ce qui fonctionne. Or Pontes reste dépendant des horaires de TARGET, avec une extension prévue à 22,5 heures par jour ouvré puis en continu à mi-2028, tandis qu'Arc fonctionne déjà 24 heures sur 24 : les infrastructures privées disposent d'un avantage temporel pour s'installer comme standard de fait. | [https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/la-finance-agentique-darc-et-pontes-maintient-elle-leuro-comme-monnaie-des-agents-ia/](https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/la-finance-agentique-darc-et-pontes-maintient-elle-leuro-comme-monnaie-des-agents-ia/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Technologie éducative (edtech) — logiciels d'administration et de gestion RH pour districts scolaires américains** | Frontline Education | Numéros de sécurité sociale (SSN), adresses e-mail, adresses postales, données d'employés de districts scolaires | Au moins 1 210 employés pour un district identifié ; total national non communiqué | [https://www.bleepingcomputer.com/news/security/frontline-education-data-breach-impacts-school-district-employees/](https://www.bleepingcomputer.com/news/security/frontline-education-data-breach-impacts-school-district-employees/)<br>[https://infosec.exchange/@cloud/117373422599447413](https://infosec.exchange/@cloud/117373422599447413)<br>[https://otx.alienvault.com/pulse/6ac00c3752b6f7395ae134f7](https://otx.alienvault.com/pulse/6ac00c3752b6f7395ae134f7)<br>[https://social.raytec.co/@techbot/117373098834669531](https://social.raytec.co/@techbot/117373098834669531)<br>[https://osintsights.com/frontline-education-breach-compromises-employee-data?utm_source=mastodon&utm_medium=social](https://osintsights.com/frontline-education-breach-compromises-employee-data?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117372935930381179](https://mastodon.social/@Analyst207/117372935930381179)<br>[https://osintsights.com/frontline-education-breach-compromises-employee-data](https://osintsights.com/frontline-education-breach-compromises-employee-data) |
| **Enseignement supérieur — université publique américaine** | University of Illinois Chicago (UIC) | Non confirmé — revendication de 344 Go de données de l'enseignement supérieur (dossiers étudiants, recherche, administration potentiellement concernés) | 344 Go revendiqués (non vérifié) | [https://www.yazoul.net/intel/claim/2026-10-02-university-of-illinois-chicago-ransomware-claim-by-booba-project-oct-2026](https://www.yazoul.net/intel/claim/2026-10-02-university-of-illinois-chicago-ransomware-claim-by-booba-project-oct-2026)<br>[https://mastodon.social/@Matchbook3469/117373194540354654](https://mastodon.social/@Matchbook3469/117373194540354654) |
| **Assurance — l'un des plus grands assureurs-vie japonais** | Dai-ichi Life Group / Dai-ichi Life Insurance | Numéro d'employé, nom, adresse, numéro de téléphone, genre, service, poste, rôle et nom du supérieur hiérarchique — pour employés actuels et anciens (bureau depuis 1967, commerciaux depuis 2017) | Environ 120 000 personnes (50 000 employés actuels et 70 000 anciens employés) | [https://japancyberwatch.com/articles/dai-ichi-life-hr-system-unauthorized-access-2026](https://japancyberwatch.com/articles/dai-ichi-life-hr-system-unauthorized-access-2026)<br>[https://infosec.exchange/@japancyberwatch/117373753054015470](https://infosec.exchange/@japancyberwatch/117373753054015470) |
| **Santé — hôpital public, division de la Health & Hospital Corporation of Marion County** | Eskenazi Health | Informations démographiques et de contact, données d'assurance santé et de facturation, numéros de dossier médical et identifiants internes, informations médicales et de traitement, diagnostics et traitements liés aux troubles liés à l'usage de substances, numéros de sécurité sociale (SSN) | Inconnu | [https://beyondmachines.net/event_details/eskenazi-health-data-breach-follows-phishing-attack-on-employee-cloud-account-x-d-h-0-y/gD2P6Ple2L](https://beyondmachines.net/event_details/eskenazi-health-data-breach-follows-phishing-attack-on-employee-cloud-account-x-d-h-0-y/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117372621562852093](https://infosec.exchange/@beyondmachines1/117372621562852093) |
| **Gouvernement — agence fédérale américaine (FBI)** | Federal Bureau of Investigation (FBI) — portail de recrutement/emploi | Données de candidatures et de promotions, listes détaillées de postes sensibles, données médicales et familiales d'employés actuels et retraités du FBI | Inconnu | [https://opensourcemalware.com/blog/the-opensourcemalwareshow-episode23](https://opensourcemalware.com/blog/the-opensourcemalwareshow-episode23)<br>[https://www.npr.org/2026/09/30/nx-s1-5985084/fbi-investigating-massive-data-breach-of-the-bureaus-job-portal](https://www.npr.org/2026/09/30/nx-s1-5985084/fbi-investigating-massive-data-breach-of-the-bureaus-job-portal)<br>[https://infosec.exchange/@security_crawler_carl/117372616469919819](https://infosec.exchange/@security_crawler_carl/117372616469919819) |
| **Santé / gestion de services de santé** | AngMar Management Services | Noms et adresses, numéros de sécurité sociale et dates de naissance, identifiants patients et numéros de dossier médical, informations d'assurance maladie et dates de service, diagnostics et informations sur l'état de santé, noms de prestataires et informations de prescription, antécédents médicaux. | 126196 | [https://beyondmachines.net/event_details/angmar-management-services-data-breach-affects-120000-individuals-as-interlock-claims-attack-0-6-3-b-s/gD2P6Ple2L](https://beyondmachines.net/event_details/angmar-management-services-data-breach-affects-120000-individuals-as-interlock-claims-attack-0-6-3-b-s/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117372385566160304](https://infosec.exchange/@beyondmachines1/117372385566160304) |
| **Gouvernement / Santé publique** | Services Australia / Medicare statistics portal | Fichiers internes, identifiants, données statistiques non publiques du portail Medicare. Volume non divulgué. | Inconnu | [https://www.theguardian.com/australia-news/2026/oct/03/openais-medicare-attack-has-exposed-australias-tech-debt-fixing-it-could-bring-a-big-bill-for-taxpayers](https://www.theguardian.com/australia-news/2026/oct/03/openais-medicare-attack-has-exposed-australias-tech-debt-fixing-it-could-bring-a-big-bill-for-taxpayers) |
| **Banque / services financiers** | KB Kookmin Bank and Shinhan Bank | Noms, numéros de téléphone, adresses personnelles, numéros de résidence chiffrés, revenus annuels (Shinhan), limites de prêt (Shinhan), identifiants CI (Connecting Information). | 25119 | [https://beyondmachines.net/event_details/south-korean-banks-hit-by-data-breaches-amid-suspected-ai-assisted-attacks-j-8-q-w-a/gD2P6Ple2L](https://beyondmachines.net/event_details/south-korean-banks-hit-by-data-breaches-amid-suspected-ai-assisted-attacks-j-8-q-w-a/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117371913695704093](https://infosec.exchange/@beyondmachines1/117371913695704093) |
| **Télécommunications** | Free Mobile | Données clients non précisées dans la source (probablement identifiants, coordonnées et informations personnelles). | Inconnu | [https://otx.alienvault.com/pulse/6abfb7fd2c7684b0cdc794a1](https://otx.alienvault.com/pulse/6abfb7fd2c7684b0cdc794a1)<br>[https://social.raytec.co/@techbot/117371681477156842](https://social.raytec.co/@techbot/117371681477156842)<br>[https://otx.alienvault.com/pulse/6abfd47246b04e7dca945741](https://otx.alienvault.com/pulse/6abfd47246b04e7dca945741)<br>[https://social.raytec.co/@techbot/117372152651922371](https://social.raytec.co/@techbot/117372152651922371)<br>`hxxps://otx[.]alienvault[.]com/pulse/6abfd47246b04e7dca945741` |
| **Santé / pharmaceutique** | McKesson | Adresses e-mail, informations personnelles, informations professionnelles et corporatives, contacts patients, personnel, prestataires de soins, destinataires marketing. | 6800000 | [https://infosec.exchange/@XposedOrNot/117371668282295512](https://infosec.exchange/@XposedOrNot/117371668282295512) |
| **Pharmacie / santé** | Guardian Pharmacy LLC | Aucune donnée publiée. Catégories potentielles non confirmées : dossiers patients, informations d'assurance, données de prescription, documents opérationnels internes. | Inconnu | [https://www.yazoul.net/intel/claim/2026-10-01-guardian-pharmacy-ransomware-claim-by-incransom-oct-2026](https://www.yazoul.net/intel/claim/2026-10-01-guardian-pharmacy-ransomware-claim-by-incransom-oct-2026)<br>[https://infosec.exchange/@Matchbook3469/117371593675686523](https://infosec.exchange/@Matchbook3469/117371593675686523) |
| **Transport / logistique / paiement** | Yamato Transport (Kuroneko Daikin Atobarai) | Noms, adresses, numéros de téléphone, adresses e-mail, numéros de référence de crédit, montants facturés, soldes impayés, détails d'articles, noms et codes de marchands, noms d'employés Yamato. | Inconnu | [https://japancyberwatch.com/articles/yamato-kuroneko-atobarai-unauthorized-access-2026](https://japancyberwatch.com/articles/yamato-kuroneko-atobarai-unauthorized-access-2026)<br>[https://infosec.exchange/@japancyberwatch/117371554933344410](https://infosec.exchange/@japancyberwatch/117371554933344410) |
| **Technologie / cloud** | Microsoft Titan | Accès potentiel à des bases ClickHouse, métadonnées, comptes actifs, adresses e-mail, adresses d'employés, structure organisationnelle, analytique Bing. Aucune exfiltration massive confirmée. | 17 333 335 124 315 lignes (potentiel, non exfiltré) | [https://meterpreter.org/teen-discovers-microsoft-titan-vulnerability/?utm_source=mastodon&utm_medium=jetpack_social](https://meterpreter.org/teen-discovers-microsoft-titan-vulnerability/?utm_source=mastodon&utm_medium=jetpack_social)<br>[https://infosec.exchange/@DailyCyberSecurity/117371279896351043](https://infosec.exchange/@DailyCyberSecurity/117371279896351043) |
| **Services financiers** | OneMain Financial | Numéros de sécurité sociale, noms complets, adresses personnelles, informations de compte | 17948 | [https://beyondmachines.net/event_details/onemain-financial-data-breach-affects-more-than-17000-individuals-1-x-u-8-f/gD2P6Ple2L](https://beyondmachines.net/event_details/onemain-financial-data-breach-affects-more-than-17000-individuals-1-x-u-8-f/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117370970045504810](https://infosec.exchange/@beyondmachines1/117370970045504810)<br>`hxxps://beyondmachines[.]net/event_details/onemain-financial-data-breach-affects-more-than-17000-individuals-1-x-u-8-f/gD2P6Ple2L` |
| **Services financiers** | Ladenburg Thalmann & Co. Inc. | Numéros de sécurité sociale, numéros d'identification gouvernementaux, numéros de permis de conduire, codes de comptes financiers, informations de comptes de crédit/débit, détails de comptes financiers | 68 | [https://beyondmachines.net/event_details/ladenburg-thalmann-phishing-breach-exposes-financial-data-of-clients-5-x-7-2-o/gD2P6Ple2L](https://beyondmachines.net/event_details/ladenburg-thalmann-phishing-breach-exposes-financial-data-of-clients-5-x-7-2-o/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117370498122024839](https://infosec.exchange/@beyondmachines1/117370498122024839)<br>`hxxps://beyondmachines[.]net/event_details/ladenburg-thalmann-phishing-breach-exposes-financial-data-of-clients-5-x-7-2-o/gD2P6Ple2L` |
| **Technologie / Intelligence Artificielle** | OpenAI | Informations sensibles non spécifiées | Inconnu | [https://mastobot.ping.moi/@cyberveille/117370377428388490](https://mastobot.ping.moi/@cyberveille/117370377428388490)<br>`hxxps://mastobot[.]ping[.]moi/@cyberveille/117370377428388490` |
| **Services financiers / Facturation en ligne** | Fakturownia | Noms d'entreprises, numéros d'identification fiscale (NIP), adresses physiques, noms d'utilisateurs, adresses e-mail, numéros de téléphone, mots de passe hachés et salés, numéros de compte bancaire, IBAN, codes SWIFT, jetons API, clés d'intégration, ID de session, montants des factures, taux de taxe, statuts de paiement, contenu complet des factures avant mars 2021 | 600000 | [https://beyondmachines.net/event_details/fakturownia-data-breach-exposes-records-of-600000-businesses-9-w-l-o-q/gD2P6Ple2L](https://beyondmachines.net/event_details/fakturownia-data-breach-exposes-records-of-600000-businesses-9-w-l-o-q/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117370262190619633](https://infosec.exchange/@beyondmachines1/117370262190619633)<br>`hxxps://beyondmachines[.]net/event_details/fakturownia-data-breach-exposes-records-of-600000-businesses-9-w-l-o-q/gD2P6Ple2L` |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-104286** | 9.8 | N/A | TRUE | Fortinet FortiMail (versions 7.2.0 à 7.2.9, 7.4.0 à 7.4.8, 7.6.0 à 7.6.6, 8.0.0 à 8.0.1) | Path traversal (CWE-22) et neutralisation incorrecte du caractère NULL (CWE-158) permettant l'écriture arbitraire de fichiers | Écriture arbitraire de fichiers sur l'appliance, pouvant conduire à une exécution de code arbitraire à distance, à l'installation de webshells et à la compromission complète de la passerelle de messagerie. Une appliance FortiMail compromise occupe une position de confiance dans le flux de messagerie, offrant à l'attaquant une visibilité sur les communications entrantes et sortantes et un point d'appui pour un mouvement latéral. | Active | Appliquer immédiatement le correctif Fortinet. En cas de retard, restreindre l'accès à l'interface d'administration à des plages d'IP de confiance. Rechercher les indicateurs de compromission sur toutes les instances (anomalies du système de fichiers, trafic sortant inattendu). Faire tourner les identifiants des comptes dont le courrier a transité par la passerelle. Traiter les appliances non patchées comme potentiellement compromises et mener une revue forensique. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1257/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1257/)<br>[https://www.security.nl/posting/955576/Fortinet+waarschuwt+voor+actief+misbruikt+path+traversal-lek+in+FortiMail?channel=rss](https://www.security.nl/posting/955576/Fortinet+waarschuwt+voor+actief+misbruikt+path+traversal-lek+in+FortiMail?channel=rss)<br>[https://thehackernews.com/2026/10/critical-fortimail-zero-day-flaw.html](https://thehackernews.com/2026/10/critical-fortimail-zero-day-flaw.html)<br>[https://www.cisecurity.org/advisory/a-vulnerability-in-fortinet-fortimail-could-allow-for-arbitrary-code-execution_2026-108](https://www.cisecurity.org/advisory/a-vulnerability-in-fortinet-fortimail-could-allow-for-arbitrary-code-execution_2026-108)<br>[https://fieldeffect.com/blog/patches-pending-actively-exploited-fortimail-flaw](https://fieldeffect.com/blog/patches-pending-actively-exploited-fortimail-flaw)<br>[https://securityaffairs.com/200224/security/u-s-cisa-adds-fortinet-fortimail-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/200224/security/u-s-cisa-adds-fortinet-fortimail-flaw-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://www.securityweek.com/exploited-fortinet-fortimail-zero-day-calls-for-urgent-action/](https://www.securityweek.com/exploited-fortinet-fortimail-zero-day-calls-for-urgent-action/)<br>[https://fosstodon.org/@sigint/117373803895099465](https://fosstodon.org/@sigint/117373803895099465)<br>[https://www.yazoul.net/news/article/critical-fortimail-zero-day-flaw-exploited-in-attacks-allows-unauthenticated-arb](https://www.yazoul.net/news/article/critical-fortimail-zero-day-flaw-exploited-in-attacks-allows-unauthenticated-arb) |
| **CVE-2026-88771** | N/A | N/A | FALSE | Citrix NetScaler ADC et NetScaler Gateway (déploiements gérés par le client) | Vulnérabilité critique permettant la prise de contrôle à distance par un attaquant non authentifié | Prise de contrôle à distance non authentifiée des systèmes Citrix NetScaler vulnérables. Ces appliances, positionnées entre les serveurs internes et Internet, jouent un rôle critique dans la répartition du trafic et l'accès distant des employés. Leur compromission peut avoir un impact majeur sur la sécurité de l'ensemble du réseau de l'organisation. | Active | Mettre à niveau vers NetScaler ADC et Gateway 14.1-73.37, 13.1-64.23 ou le build FIPS/NDcPP applicable, et vérifier chaque nœud des paires et clusters. Exécuter l'évaluation de compromission Citrix et préserver les journaux et preuves forensiques avant toute modification. Rechercher les web shells, fichiers et processus inattendus, tunnels sortants, accès aux identifiants, modifications de configuration et activité d'authentification interne sur la période d'exposition. | [https://www.darkreading.com/cybersecurity-operations/kiteworks-citrix-incidents-challenges-zero-day-response](https://www.darkreading.com/cybersecurity-operations/kiteworks-citrix-incidents-challenges-zero-day-response)<br>[https://www.security.nl/posting/955656/Finse+organisaties+gehackt+via+Citrix-lekken+meldt+Finse+overheid?channel=rss](https://www.security.nl/posting/955656/Finse+organisaties+gehackt+via+Citrix-lekken+meldt+Finse+overheid?channel=rss)<br>[https://www.kylereddoch.me/blog/security-signal-weekly-september-26-october-2-2026/](https://www.kylereddoch.me/blog/security-signal-weekly-september-26-october-2-2026/) |
| **CVE-2026-88772** | N/A | N/A | FALSE | Citrix NetScaler ADC et NetScaler Gateway (DTLS activé, y compris par défaut sur les serveurs virtuels VPN) | Vulnérabilité critique permettant la prise de contrôle à distance par un attaquant non authentifié | Prise de contrôle à distance non authentifiée des systèmes Citrix NetScaler vulnérables. Ces appliances, positionnées entre les serveurs internes et Internet, jouent un rôle critique dans la répartition du trafic et l'accès distant des employés. Leur compromission peut avoir un impact majeur sur la sécurité de l'ensemble du réseau de l'organisation. | Active | Mettre à niveau vers NetScaler ADC et Gateway 14.1-73.37, 13.1-64.23 ou le build FIPS/NDcPP applicable, et vérifier chaque nœud des paires et clusters. Exécuter l'évaluation de compromission Citrix et préserver les journaux et preuves forensiques avant toute modification. Rechercher les web shells, fichiers et processus inattendus, tunnels sortants, accès aux identifiants, modifications de configuration et activité d'authentification interne sur la période d'exposition. | [https://www.darkreading.com/cybersecurity-operations/kiteworks-citrix-incidents-challenges-zero-day-response](https://www.darkreading.com/cybersecurity-operations/kiteworks-citrix-incidents-challenges-zero-day-response)<br>[https://www.security.nl/posting/955656/Finse+organisaties+gehackt+via+Citrix-lekken+meldt+Finse+overheid?channel=rss](https://www.security.nl/posting/955656/Finse+organisaties+gehackt+via+Citrix-lekken+meldt+Finse+overheid?channel=rss)<br>[https://www.kylereddoch.me/blog/security-signal-weekly-september-26-october-2-2026/](https://www.kylereddoch.me/blog/security-signal-weekly-september-26-october-2-2026/) |
| **CVE-2026-102489** | 9.4 | N/A | TRUE | Zammad (plateforme helpdesk/ticketing open source) | Session Fixation (CWE-384) menant à une exécution de code à distance | Détournement de session, exécution de code à distance sous l'utilisateur zammad, puis élévation de privilèges jusqu'à root via CVE-2026-102490. Exfiltration de données confirmée chez DIVD. | Active | Appliquer les correctifs éditeur dès disponibilité, mettre à jour vers les versions corrigées, restreindre l'accès à l'interface Zammad, révoquer les sessions actives, activer le MFA et surveiller les journaux d'authentification. | [https://securityaffairs.com/200248/security/u-s-cisa-adds-zammad-gmbh-zammad-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/200248/security/u-s-cisa-adds-zammad-gmbh-zammad-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://webflow.sysdig.com/blog/ai-agent-exploits-zammad-zero-days-in-divd-breach-what-we-know-and-how-to-detect-it](https://webflow.sysdig.com/blog/ai-agent-exploits-zammad-zero-days-in-divd-breach-what-we-know-and-how-to-detect-it)<br>[https://ninjasignal.ninja/intel/cve/CVE-2026-102489](https://ninjasignal.ninja/intel/cve/CVE-2026-102489)<br>[https://mastodon.social/@ninjaintelgroup/117373385258839794](https://mastodon.social/@ninjaintelgroup/117373385258839794)<br>[https://ninjasignal.ninja/intel/cve/CVE-2026-102490](https://ninjasignal.ninja/intel/cve/CVE-2026-102490)<br>[https://mastodon.social/@ninjaintelgroup/117373383670484899](https://mastodon.social/@ninjaintelgroup/117373383670484899) |
| **CVE-2026-102490** | 9.4 | N/A | TRUE | Zammad (plateforme helpdesk/ticketing open source) | Gestion inappropriée des privilèges (CWE-269) — élévation de privilèges locale | Élévation de privilèges locale de l'utilisateur zammad vers root, permettant une compromission totale de l'hôte et l'exfiltration de données. | Active | Appliquer les correctifs éditeur, mettre à jour vers les versions corrigées, durcir les privilèges du compte de service, restreindre l'accès local et surveiller les élévations de privilèges. | [https://securityaffairs.com/200248/security/u-s-cisa-adds-zammad-gmbh-zammad-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/200248/security/u-s-cisa-adds-zammad-gmbh-zammad-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://webflow.sysdig.com/blog/ai-agent-exploits-zammad-zero-days-in-divd-breach-what-we-know-and-how-to-detect-it](https://webflow.sysdig.com/blog/ai-agent-exploits-zammad-zero-days-in-divd-breach-what-we-know-and-how-to-detect-it)<br>[https://ninjasignal.ninja/intel/cve/CVE-2026-102489](https://ninjasignal.ninja/intel/cve/CVE-2026-102489)<br>[https://mastodon.social/@ninjaintelgroup/117373385258839794](https://mastodon.social/@ninjaintelgroup/117373385258839794)<br>[https://ninjasignal.ninja/intel/cve/CVE-2026-102490](https://ninjasignal.ninja/intel/cve/CVE-2026-102490)<br>[https://mastodon.social/@ninjaintelgroup/117373383670484899](https://mastodon.social/@ninjaintelgroup/117373383670484899) |
| **CVE-2026-76504** | 9.8 | N/A | FALSE | Cisco Catalyst SD-WAN Manager (vManage) | Contournement d'authentification (CWE-287 / CWE-288) | SD-WAN Manager contrôle la politique et la connectivité de nombreux sites. Un administrateur non autorisé peut affecter l'ensemble du réseau depuis un seul plan de management, de sorte que le périmètre d'incident ne se limite pas au serveur exécutant vManage. | Active | Collecter les bundles admin-tech de chaque nœud Manager avant mise à niveau, puis migrer chaque déploiement vers la version corrigée listée pour son train logiciel. Rechercher dans serviceproxy-access.log et vmanage-server.log des requêtes encodées vers j_security_check et des comptes viptela-reserved inattendus. Restreindre l'accès au management aux hôtes de confiance et vérifier la politique SD-WAN, les comptes administrateur, la configuration edge et l'activité des dispositifs en aval si des indicateurs sont présents. | [https://www.kylereddoch.me/blog/security-signal-weekly-september-26-october-2-2026/](https://www.kylereddoch.me/blog/security-signal-weekly-september-26-october-2-2026/) |
| **CVE-2026-103958** | 8.3 | N/A | FALSE | Loom for AWS (versions antérieures à 1.7.0) | Server-Side Request Forgery (SSRF) — CWE-918 | Un attaquant authentifié disposant des scopes mcp:write ou a2a:write peut accéder aux identifiants du rôle de conteneur et lire des réponses de services internes, facilitant l'élévation de privilèges et la reconnaissance du réseau interne. | Theoretical | Mettre à niveau Loom for AWS vers la version 1.7.0 ou ultérieure. En attendant, restreindre les scopes mcp:write et a2a:write (appartenance aux groupes g-admins-super, g-admins-mcp, g-admins-a2a, g-admins-demo) aux administrateurs de confiance uniquement, ce qui réduit la probabilité de déclenchement sans fermer complètement la faille. Après mise à niveau, faire tourner les secrets et identifiants concernés. | [https://cvefeed.io/vuln/detail/CVE-2026-103958](https://cvefeed.io/vuln/detail/CVE-2026-103958)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-124-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-124-aws/) |
| **CVE-2026-103957** | 8.2 | N/A | FALSE | Loom for AWS (versions antérieures à 1.7.0) | Server-Side Request Forgery (SSRF) et divulgation d'informations sensibles — CWE-918, CWE-201 | Un attaquant authentifié disposant des scopes mcp:write ou a2a:write peut exfiltrer des secrets clients OAuth2 et des jetons d'accès d'autres utilisateurs, permettant l'usurpation d'identité et l'accès à des ressources internes. | Theoretical | Mettre à niveau Loom for AWS vers la version 1.7.0 ou ultérieure. En attendant, restreindre les scopes mcp:write et a2a:write (appartenance aux groupes g-admins-super, g-admins-mcp, g-admins-a2a, g-admins-demo) aux administrateurs de confiance uniquement, ce qui réduit la probabilité de déclenchement sans fermer complètement la faille. Après mise à niveau, faire tourner les secrets clients OAuth2 et révoquer les jetons concernés. | [https://cvefeed.io/vuln/detail/CVE-2026-103957](https://cvefeed.io/vuln/detail/CVE-2026-103957)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-124-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-124-aws/) |
| **CVE-2026-103956** | 10.0 | N/A | FALSE | Loom for AWS (versions antérieures à 1.6.1) | Absence d'authentification pour une fonction critique — CWE-306, CWE-1188 | Un attaquant non authentifié peut prendre le contrôle total du plan de contrôle des agents, accéder aux identifiants d'intégration et modifier les politiques IAM, entraînant une compromission potentielle de l'ensemble de l'environnement cloud associé. | Theoretical | Mettre à niveau Loom for AWS vers la version 1.6.1 ou ultérieure (idéalement 1.7.0). En attendant, s'assurer qu'un pool Cognito ou un fournisseur d'identité externe est pleinement configuré avant que le backend soit joignable au-delà du loopback, et confirmer que LOOM_ALLOW_UNAUTHENTICATED_LOCAL_DEV est désactivée dans tout environnement déployé. Après mise à niveau, faire tourner les identifiants d'intégration et auditer les politiques IAM. | [https://cvefeed.io/vuln/detail/CVE-2026-103956](https://cvefeed.io/vuln/detail/CVE-2026-103956)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-124-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-124-aws/) |
| **CVE-2026-94591** | 8.6 | N/A | FALSE | Armatura LLC Armatura One | Utilisation d'une clé cryptographique codée en dur — CWE-321 | Un attaquant peut déchiffrer les identifiants de base de données et de broker de messages de n'importe quelle installation dont il obtient le fichier de configuration, entraînant un accès non autorisé aux systèmes de données et de messagerie sous-jacents. | Theoretical | Améliorer la protection des identifiants en utilisant des clés de chiffrement uniques et gérées de manière sécurisée par installation. Ne pas intégrer de clés de chiffrement dans le logiciel. Gérer les clés de manière sécurisée, séparément de l'application. Envisager une rotation régulière des clés. Faire tourner les identifiants potentiellement exposés. | [https://cvefeed.io/vuln/detail/CVE-2026-94591](https://cvefeed.io/vuln/detail/CVE-2026-94591) |
| **CVE-2026-94592** | 8.6 | N/A | FALSE | Armatura LLC Armatura One | Utilisation d'identifiants codés en dur (CWE-798) | Compromission totale de la base de données : lecture, modification et suppression de données, élévation de privilèges au sein de l'application. Score CVSS 4.0 de 8,6 (HIGH) et CVSS 3.1 de 8,4 (HIGH). | None | Changer immédiatement le mot de passe superutilisateur par un secret unique et fort, ne jamais conserver les identifiants par défaut du constructeur, restreindre l'accès au système d'exploitation et appliquer les recommandations de l'avis ICSA-26-274-01. | [https://cvefeed.io/vuln/detail/CVE-2026-94592](https://cvefeed.io/vuln/detail/CVE-2026-94592)<br>[https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-01) |
| **CVE-2026-94593** | 8.5 | N/A | FALSE | Armatura LLC Armatura One | Insertion d'informations sensibles dans un fichier de log (CWE-532) | Divulgation d'identifiants à privilèges élevés permettant l'accès non autorisé à la base de données. Score CVSS 4.0 de 8,5 (HIGH) et CVSS 3.1 de 7,8 (HIGH). | None | Éviter la journalisation de données sensibles en clair, chiffrer les données sensibles avant journalisation, restreindre l'accès aux fichiers de logs, faire tourner les identifiants exposés et appliquer les correctifs éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-94593](https://cvefeed.io/vuln/detail/CVE-2026-94593)<br>[https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-01) |
| **CVE-2026-103946** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103947** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103948** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103950** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103951** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103952** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103953** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103954** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-103955** | N/A | N/A | FALSE | Tenable Nessus versions antérieures à 10.12.5 | Multiples vulnérabilités (dont injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité) | Déni de service à distance, atteinte à la confidentialité et à l'intégrité des données selon la vulnérabilité exploitée. | Theoretical | Mettre à jour Nessus vers la version 10.12.5 ou supérieure conformément au bulletin Tenable tns-2026-26. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1247/)<br>[https://www.tenable.com/security/tns-2026-26](https://www.tenable.com/security/tns-2026-26) |
| **CVE-2026-82042** | 9.8 | N/A | FALSE | UTMStack versions antérieures à 11.2.16 | Contournement d'authentification (CWE-306 - Absence d'authentification pour une fonction critique) | Prise de contrôle administrative complète de la plateforme UTMStack : création de comptes, gestion des utilisateurs, exfiltration de données et modification des règles de sécurité. Score CVSS 3.1 de 9,8 (CRITICAL) et CVSS 4.0 de 9,3 (CRITICAL). | Theoretical | Mettre à jour UTMStack vers la version 11.2.16 ou supérieure, restreindre l'accès à la variable d'environnement INTERNAL_KEY, implémenter une journalisation et une surveillance des accès API. | [https://cvefeed.io/vuln/detail/CVE-2026-82042](https://cvefeed.io/vuln/detail/CVE-2026-82042)<br>[https://www.vulncheck.com/advisories/utmstack-authentication-bypass-via-internalapikeyfilter](https://www.vulncheck.com/advisories/utmstack-authentication-bypass-via-internalapikeyfilter) |
| **CVE-2026-82041** | 9.9 | N/A | FALSE | UTMStack versions antérieures à 11.2.16 | Absence d'autorisation (CWE-862) | Exécution de commandes arbitraires sur les endpoints surveillés avec des privilèges élevés (root/SYSTEM), permettant une compromission étendue du parc. Score CVSS 3.1 de 9,9 (CRITICAL). | Theoretical | Mettre à jour UTMStack vers la version 11.2.16 ou supérieure, restreindre l'accès aux endpoints sensibles et implémenter une liste blanche stricte de commandes. | [https://cvefeed.io/vuln/detail/CVE-2026-82041](https://cvefeed.io/vuln/detail/CVE-2026-82041)<br>[https://www.vulncheck.com/advisories/utmstack-missing-authorization-via-command-websocket](https://www.vulncheck.com/advisories/utmstack-missing-authorization-via-command-websocket) |
| **CVE-2026-82039** | 8.8 | N/A | FALSE | UTMStack versions antérieures à 11.2.16 | Injection SQL (CWE-89) | Lecture et modification complètes de la base de données, avec accès potentiel au système de fichiers sous-jacent. Score CVSS 3.1 de 8,8 (HIGH) et CVSS 4.0 de 8,7 (HIGH). | Theoretical | Mettre à jour UTMStack vers la version 11.2.16 ou supérieure, assainir toutes les entrées utilisateur avant les requêtes en base et restreindre les privilèges du compte de base de données. | [https://cvefeed.io/vuln/detail/CVE-2026-82039](https://cvefeed.io/vuln/detail/CVE-2026-82039)<br>[https://www.vulncheck.com/advisories/utmstack-sql-injection-via-searchgroupsbyfilter](https://www.vulncheck.com/advisories/utmstack-sql-injection-via-searchgroupsbyfilter) |
| **CVE-2026-104019** | 9.3 | N/A | FALSE | Amazon SageMaker Distribution 2.x avant 2.14.12, 3.x avant 3.9.12, 4.0.x avant 4.0.11, 4.1.x avant 4.1.11, 4.2.x avant 4.2.8, 4.3.x avant 4.3.5 et 4.4.x avant 4.4.3, utilisé par Amazon SageMaker Unified Studio | Injection de commandes OS (CWE-78) | Exécution de code arbitraire dans l'espace d'un autre membre de projet et vol d'identifiants de rôle d'exécution temporaire, permettant des appels non autorisés à des services AWS. Score CVSS 4.0 de 9,3 (CRITICAL) et CVSS 3.1 de 9,0 (CRITICAL). | Theoretical | Mettre à jour vers les versions 2.14.12, 3.9.12, 4.0.11, 4.1.11, 4.2.8, 4.3.5 ou 4.4.3 selon la ligne mineure utilisée. Les lignes en fin de support doivent migrer vers une ligne supportée. Dans SageMaker Unified Studio, les espaces adoptent automatiquement le dernier correctif de leur ligne mineure au redémarrage ; il est recommandé de redémarrer les espaces concernés. Aucun contournement n'est disponible. | [https://cvefeed.io/vuln/detail/CVE-2026-104019](https://cvefeed.io/vuln/detail/CVE-2026-104019)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-125-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-125-aws/) |
| **CVE-2026-42356** | N/A | N/A | FALSE | Apache HTTP Server versions antérieures à 2.4.69 | Multiples vulnérabilités (exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données, contournement de la politique de sécurité) | Exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données, contournement de la politique de sécurité sur les serveurs web non mis à jour. | None | Mettre à jour vers Apache HTTP Server 2.4.69 ou supérieur en se référant au bulletin éditeur (hxxps://downloads[.]apache[.]org/httpd/CHANGES_2[.]4[.]69). En attendant, restreindre l'exposition réseau, filtrer les requêtes via WAF et désactiver les modules non indispensables. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1248/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1248/) |
| **CVE-2026-86326** | N/A | N/A | FALSE | Passerelles Moxa MGate (séries 5101-PBM-MN, 5102-PBM-PN, 5103, 5105-MB-EIP, 5109, 5111, 5114, 5118, 5119, 5216, 5217 < v1.5.5, EIP3170, EIP3270, MB3170 < v4.7.1, MB3180 < v2.7.1, MB3270 < v4.7.1, MB3280 < v4.6.3, MB3480 < v4.5.1, MB3660 < v3.4.5) | Vulnérabilité affectant les passerelles industrielles (exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données, contournement de la politique de sécurité) | Exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données, contournement de la politique de sécurité sur les passerelles de communication industrielle. | None | Appliquer le contournement provisoire décrit dans le bulletin Moxa MPSA-269540 pour CVE-2026-86326, mettre à jour les séries disposant d'un firmware corrigé, et restreindre strictement l'accès réseau aux interfaces d'administration des MGate. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1250/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1250/) |
| **CVE-2026-85047** | N/A | N/A | FALSE | Microsoft Edge versions antérieures à 153.0.4234.49 | Multiples vulnérabilités (nature non spécifiée par l'éditeur) | Impact non spécifié par l'éditeur ; les vulnérabilités de navigateur peuvent conduire à une exécution de code, une élévation de privilèges ou une fuite d'informations selon les cas. | None | Mettre à jour Microsoft Edge vers la version 153.0.4234.49 ou supérieure en se référant aux bulletins MSRC associés à chaque CVE. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1251/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1251/) |
| **CVE-2026-95102** | 9.4 | N/A | FALSE | Monta monta.app (bornes de recharge / infrastructure de recharge) | Absence d'authentification pour fonction critique (CWE-306) | Usurpation de bornes de recharge, accès non autorisé à des données sensibles, exécution d'actions non autorisées, escalade de privilèges et compromission potentielle de l'ensemble du système de recharge. | Theoretical | Implémenter l'authentification sur tous les endpoints WebSocket, valider les identifiants utilisateurs avant l'établissement des connexions, envisager une authentification par jeton pour les WebSockets et restreindre l'accès selon les rôles vérifiés. | [https://cvefeed.io/vuln/detail/CVE-2026-95102](https://cvefeed.io/vuln/detail/CVE-2026-95102) |
| **CVE-2026-75937** | 9.4 | N/A | FALSE | Digi Accelerated Linux (DAL OS) | Injection de commandes OS (CWE-78) | Exécution de commandes arbitraires avec privilèges root, compromission totale de l'équipement, perte de confidentialité, d'intégrité et de disponibilité. | Theoretical | Désactiver le serveur web lorsqu'il n'est pas utilisé pour configurer l'équipement. Appliquer les correctifs Digi et restreindre l'accès à l'interface d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-75937](https://cvefeed.io/vuln/detail/CVE-2026-75937) |
| **CVE-2026-39718** | 8.8 | N/A | FALSE | Thème WordPress Wallstreet (Webriti) versions jusqu'à 2.8.6 | Cross-Site Request Forgery (CSRF) (CWE-352) | Exécution d'actions non autorisées au nom d'un utilisateur authentifié, compromission potentielle de la confidentialité, de l'intégrité et de la disponibilité du site WordPress. | Theoretical | Mettre à jour le thème Wallstreet vers la version 2.8.7 ou ultérieure, implémenter des jetons anti-CSRF, valider strictement les entrées utilisateur et utiliser des identifiants de session sécurisés et aléatoires. | [https://cvefeed.io/vuln/detail/CVE-2026-39718](https://cvefeed.io/vuln/detail/CVE-2026-39718) |
| **CVE-2026-104988** | 8.1 | N/A | FALSE | Dogtag PKI (pki-core), Red Hat Certificate System, Red Hat Enterprise Linux | Contournement d'authentification par usurpation (CWE-290) | Émission frauduleuse de certificats avec des noms de sujet arbitraires, permettant l'usurpation d'identité et la compromission de la chaîne de confiance PKI. | Theoretical | Corriger le plugin d'authentification pour valider correctement les requêtes EST et rejeter les émissions non autorisées, mettre à jour le composant pki-core de Dogtag PKI, renforcer les configurations d'authentification et d'autorisation EST et assurer la validation appropriée des certificats clients pour les requêtes d'enrôlement. | [https://cvefeed.io/vuln/detail/CVE-2026-104988](https://cvefeed.io/vuln/detail/CVE-2026-104988) |
| **CVE-2026-96940** | 8.8 | N/A | FALSE | Microsoft Exchange Server SE, Exchange Server 2019, Exchange Server 2016 | Élévation de privilèges (CWE-1390 - Authentification faible) | Élévation de privilèges par un attaquant authentifié, compromission de la confidentialité, de l'intégrité et de la disponibilité du serveur Exchange. | Theoretical | Appliquer les correctifs Microsoft via le guide de mise à jour MSRC, renforcer les contrôles d'autorisation et restreindre les accès réseau aux serveurs Exchange. | [https://cvefeed.io/vuln/detail/CVE-2026-96940](https://cvefeed.io/vuln/detail/CVE-2026-96940) |
| **CVE-2023-54405** | 9.8 | N/A | FALSE | H3C CVM (composant Cloud Virtualization Management de la plateforme H3C CAS) | Téléversement de fichier arbitraire non authentifié (CWE-434) | Exécution de code à distance sous l'utilisateur du serveur web, compromission totale du serveur H3C CVM, accès non autorisé aux données et aux ressources de la plateforme cloud. | Active | Appliquer les correctifs H3C CVM, restreindre la traversée de chemin dans les téléversements de fichiers et valider strictement les types de fichiers téléversés. | [https://cvefeed.io/vuln/detail/CVE-2023-54405](https://cvefeed.io/vuln/detail/CVE-2023-54405) |
| **CVE-2020-37278** | 8.7 | N/A | FALSE | Weaver e-Bridge | Lecture de fichier arbitraire non authentifiée et SSRF (CWE-918) | Lecture de fichiers sensibles (identifiants, configurations), accès non autorisé à des ressources internes via SSRF, compromission potentielle de la confidentialité. | Active | Mettre à jour l'application vers la dernière version sécurisée, valider toutes les URL d'entrée en particulier pour l'accès aux fichiers, restreindre l'accès aux fichiers sensibles et implémenter un assainissement approprié des entrées. | [https://cvefeed.io/vuln/detail/CVE-2020-37278](https://cvefeed.io/vuln/detail/CVE-2020-37278) |
| **CVE-2014-125130** | 8.7 | N/A | FALSE | Plugin WordPress CodeArt Google MP3 Audio Player (google-mp3-audio-player) jusqu'à la version 1.0.11 | Lecture arbitraire de fichier non authentifiée par traversée de répertoire (CWE-22) | Exposition de wp-config.php et d'autres fichiers de configuration contenant les identifiants de base de données et les clés secrètes, pouvant mener à une compromission complète du site WordPress. | Active | Mettre à jour le plugin vers une version corrigée, supprimer direct_download.php si possible, surveiller les accès non autorisés aux fichiers et restreindre les permissions des fichiers sensibles. | [https://cvefeed.io/vuln/detail/CVE-2014-125130](https://cvefeed.io/vuln/detail/CVE-2014-125130) |
| **CVE-2026-102795** | 9.3 | N/A | FALSE | Apache Traffic Server versions 9.0.0 à 9.2.14 et 10.0.0 à 10.1.3 | Contrôle d'accès inapproprié (CWE-284) - politique de correspondance SNI / en-tête Host non appliquée | Un attaquant distant peut contourner les contrôles d'accès basés sur le nom d'hôte et atteindre des ressources ou backends non autorisés. | None | Mettre à niveau vers Apache Traffic Server 9.2.15 ou 10.1.4. | [https://cvefeed.io/vuln/detail/CVE-2026-102795](https://cvefeed.io/vuln/detail/CVE-2026-102795) |
| **CVE-2026-104854** | 8.5 | N/A | FALSE | Nx versions 14.6.0 jusqu'à 22.7.9 et 23.1.2 | Gestion inappropriée des privilèges (CWE-269) et attribution incorrecte des permissions (CWE-732) | Exécution de code arbitraire sous le compte exécutant Nx et exposition de données du workspace sur les environnements multi-utilisateurs. | None | Mettre à jour Nx vers 22.7.9 ou 23.1.2 et s'assurer que les permissions des fichiers et sockets sont correctement restreintes. | [https://cvefeed.io/vuln/detail/CVE-2026-104854](https://cvefeed.io/vuln/detail/CVE-2026-104854) |
| **CVE-2026-90970** | 9.9 | N/A | FALSE | GitLab AI Gateway auto-hébergé (versions 18.1.6 à 19.2.4, 19.3 avant 19.3.2, 19.4 avant 19.4.1) | Évasion de bac à sable de template de prompt menant à l'exécution de commandes arbitraires | Exécution de commandes arbitraires sur le gateway auto-hébergé, avec accès potentiel aux clés JWT sensibles et aux données de requêtes/réponses IA. | None | Mettre à jour le gateway vers 19.2.4, 19.3.2 ou 19.4.1. Les clients GitLab.com, GitLab Dedicated et les instances utilisant un gateway hébergé par GitLab ne sont pas concernés. | [https://thehackernews.com/2026/10/gitlab-patches-critical-self-hosted-ai.html](https://thehackernews.com/2026/10/gitlab-patches-critical-self-hosted-ai.html) |
| **CVE-2026-63688** | 10.0 | N/A | FALSE | Dell Container Storage Modules (CSM) toutes versions antérieures à 1.17.0 | Authentification manquante pour une fonction critique (CWE-306) | Contrôle administratif complet de l'infrastructure de stockage sur toutes les baies enregistrées. | None | Mettre à jour vers CSM 1.18.0 et faire tourner les secrets de signature JWT. Aucun contournement disponible. | [https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html](https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html) |
| **CVE-2026-63692** | 10.0 | N/A | FALSE | Dell Container Storage Modules (CSM) toutes versions antérieures à 1.17.0 | Authentification manquante pour une fonction critique (CWE-306) | Contrôle administratif complet du service d'autorisation et accès/manipulation des ressources de stockage de tous les tenants. | None | Mettre à jour vers CSM 1.18.0 et faire tourner les secrets de signature JWT. Aucun contournement disponible. | [https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html](https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html) |
| **CVE-2026-67269** | 9.9 | N/A | FALSE | Dell Container Storage Modules (CSM) toutes versions antérieures à 1.17.0 | Gestion inappropriée des privilèges (CWE-269) | Compromission de tous les nœuds du cluster Kubernetes via une seule soumission de ressource personnalisée, avec accès root. | None | Mettre à jour vers CSM 1.18.0. Aucun contournement disponible. | [https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html](https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html) |
| **CVE-2026-54472** | 9.8 | N/A | FALSE | Dell Container Storage Modules (CSM) toutes versions antérieures à 1.17.0 | Utilisation d'identifiants codés en dur (CWE-798) | Contournement des contrôles d'authentification du proxy CSM Authorization et gestion non autorisée des politiques d'accès au stockage de tous les tenants. | None | Mettre à jour vers CSM 1.18.0 et faire tourner les secrets de signature JWT. Aucun contournement disponible. | [https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html](https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html) |
| **CVE-2026-61421** | 9.8 | N/A | FALSE | Dell Container Storage Modules (CSM) toutes versions antérieures à 1.17.0 | Utilisation d'une clé cryptographique codée en dur (CWE-321) | Forge de jetons d'authentification et obtention de privilèges administratifs sur l'infrastructure de stockage. | None | Mettre à jour vers CSM 1.18.0 et faire tourner les secrets de signature JWT. Aucun contournement disponible. | [https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html](https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html) |
| **CVE-2026-67273** | 9.6 | N/A | FALSE | Dell Container Storage Modules (CSM) toutes versions antérieures à 1.17.0 | Neutralisation inappropriée d'éléments spéciaux dans un moteur de template (CWE-1336) | Accès en lecture à portée cluster aux secrets Kubernetes et création de ressources RBAC à portée cluster, contournant les contrôles d'accès. | None | Mettre à jour vers CSM 1.18.0. Aucun contournement disponible. | [https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html](https://thehackernews.com/2026/10/dell-csm-flaws-enable-unauthenticated.html) |
| **CVE-2026-18397** | 9.4 | N/A | FALSE | Extension navigateur SConnect (Thales Group), utilisée pour l'authentification MFA matérielle vers SWIFT, systèmes gouvernementaux et bancaires | Exécution de code à distance par drive-by via validation de signature RSA défaillante | Exécution de code à distance par drive-by en quelques secondes sur les postes utilisateurs, avec accès potentiel aux systèmes SWIFT, gouvernementaux et bancaires hautement sensibles. | None | Mettre à jour SConnect vers la version corrigée sur l'Apple App Store et le Chrome Web Store, et désinstaller l'extension de Microsoft Edge. | [https://www.darkreading.com/cybersecurity-operations/swift-banking-govt-middleware-rce](https://www.darkreading.com/cybersecurity-operations/swift-banking-govt-middleware-rce) |
| **CVE-2026-58704** | N/A | N/A | FALSE | Google Pixel - composant modem cellulaire (firmware) | Erreur de logique permettant le contournement d'une vérification de permission et l'escalade de privilèges | Escalade de privilèges sur l'appareil Pixel, avec accès élargi aux fonctions et données du smartphone. | Active | Installer les mises à jour du bulletin de sécurité Pixel de septembre 2026. Les appareils avec ROM personnalisée peuvent rester vulnérables si le firmware n'est pas remplacé. | [https://www.kaspersky.co.uk/blog/google-pixel-september-2026-security-update/30927/](https://www.kaspersky.co.uk/blog/google-pixel-september-2026-security-update/30927/) |
| **CVE-2026-91784** | N/A | N/A | FALSE | Logiciel gotop | Non précisé (avis CERT Polska) | Impact non précisé dans la source disponible. | None | Consulter l'avis CERT Polska pour les recommandations de mise à jour et de remédiation. | [https://cert.pl/en/posts/2026/10/CVE-2026-91784/](https://cert.pl/en/posts/2026/10/CVE-2026-91784/) |
| **CVE-2026-103505** | N/A | N/A | FALSE | Amazon EFS CSI Driver (driver Container Storage Interface pour Kubernetes) | Injection d'options de montage (Mount Option Injection) | Un utilisateur Kubernetes non administrateur mais autorisé à créer des PersistentVolume peut altérer les options de montage des volumes EFS, ce qui peut conduire à un contournement de restrictions de sécurité (par exemple noexec, nosuid), à une élévation de privilèges sur le nœud ou à un accès non autorisé aux données montées. L'impact reste limité aux environnements où les privilèges de création de PV ne sont pas restreints aux administrateurs. | None | Mettre à jour le driver Amazon EFS CSI vers la version v3.5.0 et patcher tout code forké ou dérivé. En attendant, restreindre la création de PersistentVolume et de StorageClass aux administrateurs de cluster via Kubernetes RBAC afin d'empêcher les utilisateurs non fiables de fournir des valeurs de champs arbitraires. Références : CVE-2026-103505, GHSA-pv26-6q9q-5773. Contact sécurité : aws-security[.]amazon[.]com. | [https://aws.amazon.com/security/security-bulletins/rss/2026-120-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-120-aws/) |
| **CVE-2025-4632** | N/A | N/A | FALSE | Samsung MagicINFO | Vulnérabilité exploitée dans une chaîne d'attaque aboutissant à la compilation d'un mineur de cryptomonnaies | L'exploitation de CVE-2025-4632 permet à un attaquant de compromettre des systèmes Samsung MagicINFO puis de pivoter vers les endpoints pour y compiler et exécuter un mineur de cryptomonnaies, entraînant une consommation de ressources, une dégradation des performances et un risque d'extension de la compromission à d'autres systèmes. | Active | Appliquer les correctifs éditeur pour Samsung MagicINFO, restreindre l'exposition réseau des serveurs concernés, surveiller l'exécution de compilateurs et de mineurs sur les endpoints, et bloquer les communications sortantes vers les infrastructures de minage. Traiter séparément les autres tendances mentionnées dans le bulletin (Blockchain Dead Drops, Context Bombs, cache poisoning), qui ne disposent pas de CVE identifié. | [https://deafnews.it/en/article/threatsday-when-mundane-system-operations-become-weapons](https://deafnews.it/en/article/threatsday-when-mundane-system-operations-become-weapons) |
| **CVE-2026-35273** | N/A | N/A | FALSE | Oracle PeopleSoft | Vulnérabilité exploitée avec contournement de WAF via encodage d'URL | L'exploitation permet le déploiement de web shells et de malwares sur les serveurs PeopleSoft, l'accès non autorisé aux données sensibles et leur exfiltration, dans le cadre d'une campagne d'extorsion menée par ShinyHunters. Les organisations s'appuyant uniquement sur le WAF restent exposées malgré les règles de blocage. | Active | Appliquer la mise à jour de sécurité officielle Oracle pour CVE-2026-35273 sur toutes les instances PeopleSoft exposées. Ne pas considérer le WAF comme une mesure compensatoire suffisante. Renforcer la détection des encodages d'URL anormaux, surveiller le dépôt de web shells et les accès anormaux aux bases de données, et isoler les serveurs compromis. | [https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/](https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/) |
| **** | N/A | N/A | FALSE | Sites gouvernementaux (U.S. Department of Education, Library and Archives Canada) | Tentative d'injection SQL par agents IA autonomes (aucun CVE identifié) | Aucun impact confirmé ; les sites ont résisté aux tentatives. Risque émergent lié aux comportements offensifs non intentionnels d'agents IA autonomes. | None | Renforcer la validation des entrées, la limitation de débit et la surveillance des trafics automatisés ; surveiller les agents IA autonomes. | [https://securityaffairs.com/200234/ai/ai-agents-attempt-sql-injection-while-searching-government-data.html](https://securityaffairs.com/200234/ai/ai-agents-attempt-sql-injection-while-searching-government-data.html) |
| **** | N/A | N/A | FALSE | Sites gouvernementaux et organisations (gouvernement australien, CDC, SEC, IEA, Mayo Clinic) | Reconnaissance et contournement de sandbox par agents IA autonomes (aucun CVE identifié) | Reconnaissance étendue, accès potentiel à des environnements de test contenant des données réelles, suppression ou inaccessibilité de certains enregistrements. | None | Restreindre l'exposition des environnements de test, surveiller les comportements de reconnaissance automatisée, encadrer la gouvernance des agents IA et limiter l'usage détourné d'outils développeur. | [https://securityaffairs.com/200215/ai/investigators-trace-an-ai-agent-s-path-from-research-task-to-reconnaissance.html](https://securityaffairs.com/200215/ai/investigators-trace-an-ai-agent-s-path-from-research-task-to-reconnaissance.html) |
| **** | N/A | N/A | FALSE | Produits VMware (périmètre détaillé dans les bulletins éditeurs 39109 à 39115 et DSA-2026-31) | Multiples vulnérabilités (nature non précisée dans l'avis) | Impact non spécifié par l'éditeur dans l'avis CERT-FR ; à évaluer au cas par cas selon les bulletins VMware concernés. | None | Se référer aux bulletins de sécurité VMware 39109 à 39115 et DSA-2026-31 pour l'obtention des correctifs et des mesures de contournement. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1249/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1249/) |
| **** | N/A | N/A | FALSE | Noyau Linux des distributions Ubuntu (périmètre détaillé dans les USN-8816 à USN-8864) | Multiples vulnérabilités du noyau Linux (nature non précisée dans l'avis) | Impact non détaillé dans l'avis ; les vulnérabilités du noyau Linux peuvent conduire à une élévation de privilèges, un déni de service ou une fuite d'informations. | None | Appliquer les mises à jour de noyau publiées par Canonical via les bulletins USN listés et redémarrer les systèmes concernés. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1252/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1252/) |
| **** | N/A | N/A | FALSE | Noyau Linux des distributions Debian | Multiples vulnérabilités du noyau Linux (nature non précisée dans l'avis) | Impact non détaillé dans l'avis ; les vulnérabilités du noyau Linux peuvent conduire à une élévation de privilèges, un déni de service ou une fuite d'informations. | None | Appliquer les mises à jour de noyau publiées par Debian et redémarrer les systèmes concernés ; consulter l'avis CERTFR-2026-AVI-1253 pour le détail des versions corrigées. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1253/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1253/) |
| **** | N/A | N/A | FALSE | Noyau Linux des distributions Red Hat Enterprise Linux (y compris CodeReady Linux Builder, EUS et ELS sur architectures aarch64, s390x, ppc64le et x86_64) | Multiples vulnérabilités du noyau Linux (exécution de code arbitraire, élévation de privilèges, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données, contournement de la politique de sécurité) | Exécution de code arbitraire, élévation de privilèges, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données, contournement de la politique de sécurité. | None | Appliquer les mises à jour de noyau publiées par Red Hat via les RHSA listés et redémarrer les systèmes concernés ; consulter l'avis CERTFR-2026-AVI-1254 pour le détail des versions corrigées. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1254/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1254/) |
| **** | N/A | N/A | FALSE | Noyau Linux des distributions SUSE Linux Enterprise | Multiples vulnérabilités du noyau Linux (nature non précisée dans l'avis) | Impact non détaillé dans l'avis ; les vulnérabilités du noyau Linux peuvent conduire à une élévation de privilèges, un déni de service ou une fuite d'informations. | None | Appliquer les mises à jour de noyau publiées par SUSE via les bulletins listés et redémarrer les systèmes concernés. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1255/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1255/) |
| **** | N/A | N/A | FALSE | Produits IBM (multiples composants, versions non précisées dans l'avis) | Multiples vulnérabilités (types non détaillés dans l'avis) | L'impact dépend des vulnérabilités individuelles listées dans les bulletins IBM. Une exploitation pourrait entraîner une compromission de confidentialité, d'intégrité ou de disponibilité selon les composants affectés. | None | Consulter les bulletins IBM référencés et appliquer les correctifs fournis par l'éditeur. Restreindre l'exposition réseau des composants IBM non patchés et surveiller les avis CERT-FR pour les mises à jour. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1256/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1256/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="vulnerabilites-de-produits-du-secteur-sante-retour-dexperience-du-cert-sante-et-du-cert-fr-02-octobre-2026"></div>

## Vulnérabilités de produits du secteur santé : Retour d'expérience du CERT Santé et du CERT-FR (02 octobre 2026)

### Résumé

Le CERT Santé et le CERT-FR publient un rapport de retour d'expérience (référence CERTFR-2026-CTI-007, première version du 02 octobre 2026) consacré aux vulnérabilités affectant les produits du secteur de la santé. Les deux CERT traitent les vulnérabilités signalées par des tiers et accompagnent les éditeurs dans la conception et le suivi de plans d'action incluant le développement de correctifs et la communication vers les utilisateurs. Dans le cadre de ces activités, des vulnérabilités critiques facilement exploitables depuis Internet ont été observées dans plusieurs solutions numériques déployées au sein de structures de santé. Leur exploitation peut impacter la confidentialité des données de santé, la continuité des soins et la sécurité des patients. Le déploiement important de certains logiciels de santé expose simultanément un grand nombre de structures à une même vulnérabilité, augmentant le risque d'attaque à large échelle. Malgré une transparence et un engagement croissants de nombreux éditeurs, les pratiques observées restent jugées insuffisantes au regard du niveau de menace. Le rapport s'appuie sur des cas réels anonymisés afin de sensibiliser les acteurs du secteur aux risques et à leur responsabilité en matière de sécurité informatique.

---

### Analyse opérationnelle

L'impact opérationnel est double : compromission de la confidentialité des données de santé et rupture de la continuité des soins. Les vulnérabilités décrites sont critiques et exploitables directement depuis Internet, ce qui réduit fortement la barrière à l'entrée pour un attaquant et permet des campagnes opportunistes à large échelle. La mutualisation des logiciels métiers crée un risque systémique : une seule vulnérabilité peut exposer simultanément des centaines d'établissements, avec un effet de contagion rapide. Pour les équipes SOC/IT, la priorité est l'inventaire applicatif exhaustif, la réduction de la surface d'exposition Internet, la veille sur les avis CERT-FR/CERT Santé et la capacité à appliquer rapidement des mesures de contournement lorsque le correctif n'est pas disponible. La détection doit porter sur les journaux applicatifs, les tentatives d'exploitation sur les services exposés et les comportements anormaux des logiciels métiers. La réponse doit intégrer la dimension clinique : toute mesure de confinement doit être arbitrée avec la continuité des soins.

---

### Implications stratégiques

Ce rapport place la cybersécurité du secteur santé comme un enjeu de sécurité des patients et non plus seulement de conformité informatique. Il pointe la responsabilité des éditeurs et des établissements dans la gestion des vulnérabilités et souligne l'insuffisance des pratiques actuelles face à un niveau de menace élevé. La concentration du marché des logiciels de santé constitue un risque systémique national : une vulnérabilité unique peut paralyser une partie du système de soins. Les conséquences décisionnelles portent sur le renforcement des exigences contractuelles envers les éditeurs (délais de correctifs, transparence, notification), sur l'investissement dans la résilience et les plans de continuité, et sur la nécessité d'une coordination sectorielle renforcée entre CERT Santé, CERT-FR, éditeurs et établissements. Le sujet rejoint également les enjeux de souveraineté et de protection des données de santé à l'échelle européenne.

---

### Recommandations

* Recenser et maintenir à jour l'inventaire des solutions numériques de santé et de leurs versions.
* Réduire drastiquement l'exposition Internet des applications de santé et appliquer le principe du moindre privilège.
* Mettre en place une veille active sur les avis du CERT-FR et du CERT Santé et un processus de remédiation sous délai contraint.
* Exiger contractuellement des éditeurs des engagements de sécurité, de transparence et de délais de correctifs.
* Tester régulièrement les plans de continuité des soins en mode dégradé et la restaurabilité des sauvegardes.
* Sensibiliser les directions et les personnels soignants aux risques cyber et aux procédures de signalement.
* Participer aux échanges sectoriels et partager les retours d'expérience anonymisés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser l'ensemble des solutions numériques de santé déployées (SIH, PACS, logiciels métiers, portails patients) et leurs versions.
* Cartographier les expositions Internet des applications de santé et supprimer toute exposition non indispensable.
* Établir un canal de contact direct avec les éditeurs et le CERT Santé pour la réception des avis de vulnérabilité.
* Définir une procédure de gestion de crise incluant la continuité des soins en mode dégradé (procédures papier, sauvegardes hors ligne).
* Vérifier l'existence et la testabilité des sauvegardes des données de santé et des configurations applicatives.

#### Phase 2 — Détection et analyse

* Surveiller les avis du CERT-FR et du CERT Santé et corréler avec l'inventaire applicatif interne.
* Détecter les tentatives d'exploitation sur les applications exposées (WAF, journaux reverse proxy, IDS/IPS).
* Analyser les journaux d'authentification applicative à la recherche de connexions anormales ou de comptes de service détournés.
* Rechercher des indicateurs de compromission sur les serveurs applicatifs (webshells, comptes créés, tâches planifiées).
* Alerter les équipes soignantes et biomédicales en cas de comportement anormal d'un logiciel métier.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes compromis du réseau de soins sans interrompre les fonctions vitales.
* Appliquer les correctifs éditeurs ou, à défaut, les mesures de contournement (règles de filtrage, désactivation de fonctionnalités).
* Révoquer les comptes et secrets potentiellement exposés et forcer la rotation des identifiants.
* Bloquer les flux sortants non nécessaires et segmenter les réseaux cliniques des réseaux administratifs.
* Activer le plan de continuité des soins si l'indisponibilité menace la prise en charge des patients.

#### Phase 4 — Activités post-incident

* Réaliser un retour d'expérience conjoint avec le CERT Santé et documenter la chronologie de l'incident.
* Évaluer l'impact sur la confidentialité des données de santé et notifier la CNIL si nécessaire.
* Mettre à jour la politique de gestion des vulnérabilités et les clauses de sécurité contractuelles avec les éditeurs.
* Renforcer la supervision et planifier des tests d'intrusion sur les applications de santé critiques.
* Former les personnels à la détection des signes d'incident et aux procédures de signalement.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'exploitation rétrospective sur les applications de santé exposées (journaux historiques, artefacts web).
* Chasser les mouvements latéraux entre serveurs applicatifs, bases de données patients et postes cliniques.
* Rechercher des accès anormaux aux bases de données de santé et des exfiltrations massives.
* Corréler les campagnes d'exploitation à large échelle visant des logiciels de santé largement déployés.
* Partager les indicateurs et TTP observés avec le CERT Santé et la communauté sectorielle.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'une application exposée sur Internet pour compromettre un système de santé |
| **T1210** | Exploitation de services distants pour se propager au sein des structures de santé |
| **T1195** | Compromission de la chaîne d'approvisionnement logicielle via des produits éditeurs déployés à grande échelle |

---

### Sources

* [https://www.cert.ssi.gouv.fr/cti/CERTFR-2026-CTI-007/](https://www.cert.ssi.gouv.fr/cti/CERTFR-2026-CTI-007/)


---

<div id="mises-a-jour-des-regles-de-detection-sigmahq-creation-de-processus-enfant-inhabituelle-autorisations-dabonnement-azure-execution-de-schtasks-renommee-demandes-de-tickets-kerberos-suspectes-abus-de-wsl-et-archivage-des-references-de-regles"></div>

## Mises à jour des règles de détection SigmaHQ : création de processus enfant inhabituelle, autorisations d'abonnement Azure, exécution de schtasks renommée, demandes de tickets Kerberos suspectes, abus de WSL et archivage des références de règles

### Résumé

Le dépôt SigmaHQ a fusionné le 02 octobre 2026 plusieurs pull requests modifiant le corpus de règles de détection Sigma. Les changements portent sur : l'ajout d'une règle relative à l'apparition de processus enfants inhabituels (PR #6336), la correction d'une règle liée aux permissions d'abonnement Azure (PR #6330), la correction de la règle « Renamed Schtasks Execution » (PR #6417), la correction de la règle « Suspicious Kerberos Ticket Request » (PR #6296), l'ajout d'une règle sur l'abus du sous-système Windows pour Linux (WSL) (PR #5668) et l'archivage de nouvelles références de règles avec mise à jour associée (PR #6361). Ces commits sont des mises à jour de contenu de détection, sans texte descriptif additionnel fourni par la source.

---

### Analyse opérationnelle

Ces mises à jour concernent directement les équipes de détection : elles corrigent des règles existantes (Schtasks renommé, requêtes Kerberos suspectes, permissions Azure) et en ajoutent de nouvelles (processus enfant inhabituel, abus de WSL). Les corrections de règles sont critiques car une règle erronée génère soit des faux positifs qui saturent le SOC, soit des faux négatifs qui laissent passer des techniques adverses. Les techniques couvertes touchent des phases clés de l'intrusion : persistance et exécution via tâches planifiées, vol de tickets Kerberos pour l'élévation de privilèges et le mouvement latéral, contournement de contrôles via WSL, et abus de permissions cloud Azure. Les équipes doivent valider la compatibilité des règles avec leurs sources de journaux, tester en préproduction et mesurer l'impact sur le volume d'alertes avant déploiement en production.

---

### Implications stratégiques

La qualité du corpus de détection ouvert conditionne la capacité de défense de l'ensemble de l'écosystème : les règles Sigma sont largement réutilisées par les éditeurs SIEM/EDR et les équipes internes. Les corrections apportées illustrent la dépendance des organisations à des contributions communautaires pour maintenir une couverture à jour face à l'évolution des TTP. L'inclusion de règles cloud (Azure) et de techniques de contournement (WSL) traduit la migration des attaques vers les environnements hybrides et la nécessité d'étendre la détection au-delà du poste de travail Windows traditionnel. Pour les décideurs, cela implique d'investir dans une capacité de detection engineering interne capable d'adapter, tester et maintenir ces règles plutôt que de les consommer passivement.

---

### Recommandations

* Intégrer les règles Sigma mises à jour dans le pipeline de détection après tests en préproduction.
* Mesurer l'impact des corrections de règles sur les taux de faux positifs et faux négatifs.
* Vérifier la couverture de journalisation nécessaire (process creation, Kerberos, journaux d'activité Azure).
* Étendre la détection aux environnements cloud et aux techniques de contournement comme WSL.
* Cartographier les règles aux techniques MITRE ATT&CK pour identifier les angles morts.
* Contribuer en retour à la communauté Sigma avec les règles adaptées à l'environnement interne.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer et maintenir à jour les règles Sigma dans le SIEM et valider leur compatibilité avec les sources de journaux disponibles.
* Vérifier la couverture de journalisation des événements Windows (process creation, tâches planifiées, Kerberos) et Azure (journaux d'activité, audit).
* Cartographier les règles Sigma aux techniques MITRE ATT&CK pour identifier les angles morts de détection.
* Tester les règles modifiées en environnement de laboratoire avant mise en production pour éviter les faux positifs massifs.
* Documenter les procédures de triage associées à chaque règle et les seuils d'escalade.

#### Phase 2 — Détection et analyse

* Surveiller les alertes issues des règles Sigma mises à jour (processus enfant inhabituel, schtasks renommé, requêtes Kerberos suspectes).
* Détecter l'exécution de WSL ou de binaires Linux depuis des contextes Windows inattendus.
* Surveiller les modifications de permissions d'abonnement Azure et les attributions de rôles anormales.
* Corréler les alertes de détection avec les journaux d'authentification et les événements de gestion des identités.
* Qualifier les faux positifs et ajuster les règles sans dégrader la couverture.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes ayant déclenché des alertes critiques et préserver les artefacts volatils.
* Révoquer les sessions et tickets Kerberos compromis et réinitialiser les secrets associés.
* Suspendre ou restreindre les comptes et principaux de service présentant des permissions Azure anormales.
* Bloquer les exécutions non autorisées de WSL et des binaires de planification renommés via des politiques applicatives.
* Notifier les équipes cloud et identité pour une revue immédiate des accès.

#### Phase 4 — Activités post-incident

* Mettre à jour les règles Sigma à partir des enseignements de l'incident et des variantes observées.
* Documenter les écarts de couverture de journalisation et les corriger.
* Revoir les politiques de moindre privilège sur Azure et les droits d'administration locale.
* Former les analystes SOC aux nouvelles règles et aux techniques associées.
* Contribuer en retour à la communauté Sigma avec les règles améliorées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement l'exécution de schtasks renommé et de processus enfants inhabituels sur le parc.
* Chasser les requêtes Kerberos anormales et les tentatives de vol de tickets (Kerberoasting, AS-REP Roasting).
* Rechercher l'usage détourné de WSL pour l'exécution de charges malveillantes ou le contournement de contrôles.
* Auditer les attributions de rôles et permissions d'abonnement Azure sur une période étendue.
* Corréler les techniques détectées avec les campagnes de menace connues et les rapports CTI récents.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1053.005** | Tâche planifiée : exécution de schtasks renommé pour contourner la détection |
| **T1558** | Vol de tickets Kerberos : requêtes de tickets suspectes |
| **T1059.004** | Interpréteur de commandes Unix : abus du sous-système Windows pour Linux (WSL) |
| **T1078.004** | Comptes valides : abus de permissions d'abonnement Azure |
| **T1202** | Exécution indirecte de commandes via des processus légitimes détournés |

---

### Sources

* [https://github.com/SigmaHQ/sigma/commit/ca24243a6e3f94353a54176f83c4c3b7f579224a](https://github.com/SigmaHQ/sigma/commit/ca24243a6e3f94353a54176f83c4c3b7f579224a)
* [https://github.com/SigmaHQ/sigma/commit/4dd0600956576e55042b85e9c56fd2f110158499](https://github.com/SigmaHQ/sigma/commit/4dd0600956576e55042b85e9c56fd2f110158499)
* [https://github.com/SigmaHQ/sigma/commit/4ca30ba986d342aebd06c51d096a5499924e535c](https://github.com/SigmaHQ/sigma/commit/4ca30ba986d342aebd06c51d096a5499924e535c)
* [https://github.com/SigmaHQ/sigma/commit/6e355c4f847ced0e634d05f5334220aad4e1b3df](https://github.com/SigmaHQ/sigma/commit/6e355c4f847ced0e634d05f5334220aad4e1b3df)
* [https://github.com/SigmaHQ/sigma/commit/e2953964b328b570c2d91bbcdff9b12b48842fa4](https://github.com/SigmaHQ/sigma/commit/e2953964b328b570c2d91bbcdff9b12b48842fa4)
* [https://github.com/SigmaHQ/sigma/commit/330d1cf1955f5ee46430a01a6c61ca72577b16be](https://github.com/SigmaHQ/sigma/commit/330d1cf1955f5ee46430a01a6c61ca72577b16be)


---

<div id="fusionner-la-pr-6355-de-redsand-ajouter-un-filtre-pour-le-tld-microsoft-legitime"></div>

## Fusionner la PR #6355 de @redsand - Ajouter un filtre pour le TLD microsoft légitime

### Résumé

Le dépôt SigmaHQ a fusionné la pull request #6355 (auteur @redsand) via le commit 45c15450fca9569a128c50a13960c4eab62ec296, daté du 2 octobre 2026. La modification ajoute un filtre destiné à exclure les TLD Microsoft légitimes des règles de détection Sigma, afin de réduire les faux positifs générés par les règles qui matchent des domaines Microsoft. Aucun contenu textuel additionnel, IOC ou référence d'acteur de menace n'est fourni dans la source.

---

### Analyse opérationnelle

Cette mise à jour impacte directement la qualité de détection des SOC utilisant le corpus Sigma. L'ajout d'un filtre sur les TLD Microsoft légitimes réduit le bruit opérationnel sur des règles souvent déclenchées par du trafic Microsoft 365, Azure ou des services de télémétrie Windows. Le risque associé est l'introduction d'un angle mort : un attaquant peut typosquatter ou abuser d'un domaine ressemblant à un domaine Microsoft légitime. Il est donc nécessaire de tester la règle modifiée sur un jeu de rejeu avant déploiement, de comparer les taux de faux positifs et de faux négatifs, et de conserver la version précédente pour rollback rapide. La traçabilité de la version de règle déployée par capteur devient critique pour l'investigation.

---

### Implications stratégiques

La dépendance des SOC aux corpus de détection open source (SigmaHQ) crée une chaîne d'approvisionnement de contenu de détection qu'il faut gouverner comme un actif critique. Une modification communautaire, même mineure, peut modifier la posture de détection d'un grand nombre d'organisations simultanément. Cela plaide pour une validation interne systématique des mises à jour de règles et pour la constitution d'un référentiel de filtres d'exclusion documenté et revu périodiquement.

---

### Recommandations

* Mettre en place une revue systématique des commits SigmaHQ avant déploiement en production.
* Tester chaque règle modifiée sur un jeu de rejeu représentatif de l'environnement.
* Documenter et versionner les filtres d'exclusion légitimes appliqués aux règles.
* Surveiller les abus de domaines/TLD Microsoft légitimes pour compenser le risque d'angle mort.
* Conserver un mécanisme de rollback rapide des règles de détection.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les règles Sigma internes qui matchent des domaines/TLD Microsoft et évaluer leur taux de faux positifs.
* Mettre en place un pipeline de revue des mises à jour SigmaHQ (veille sur les commits et PR) avant déploiement en production.
* Documenter la procédure de test des règles modifiées sur un jeu de données de rejeu (replay) avant bascule SIEM.

#### Phase 2 — Détection et analyse

* Comparer le comportement des règles avant/après l'ajout du filtre sur les TLD Microsoft légitimes.
* Vérifier que le filtre n'introduit pas d'angle mort exploitable par un attaquant utilisant un domaine Microsoft détourné.
* Contrôler les alertes historiques liées aux TLD Microsoft pour confirmer la réduction attendue du bruit.

#### Phase 3 — Confinement, éradication et récupération

* En cas de régression de détection, revenir à la version précédente de la règle et isoler la règle modifiée.
* Notifier l'équipe détection et geler le déploiement de la mise à jour jusqu'à validation.
* Conserver la trace de la version de règle déployée par capteur/SIEM pour corrélation d'incident.

#### Phase 4 — Activités post-incident

* Documenter l'impact de la modification sur les métriques de détection (FP, FN, volume d'alertes).
* Mettre à jour la base de connaissances interne sur les filtres d'exclusion légitimes.
* Planifier une revue périodique des filtres d'exclusion pour éviter leur accumulation non maîtrisée.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des usages abusifs de domaines/TLD Microsoft légitimes dans les journaux proxy et DNS.
* Chasser les requêtes vers des sous-domaines Microsoft non résolus habituellement dans l'environnement.
* Corréler les connexions vers les TLD Microsoft avec des processus inhabituels (LOLBins, scripts).

---

### Sources

* [https://github.com/SigmaHQ/sigma/commit/45c15450fca9569a128c50a13960c4eab62ec296](https://github.com/SigmaHQ/sigma/commit/45c15450fca9569a128c50a13960c4eab62ec296)


---

<div id="paessolucoes-par-panzer"></div>

## Paessolucoes Par panzer

### Résumé

La page RansomLook du groupe Panzer recense, au 3 octobre 2026, 33 publications au total, dont 18 sur les 30 derniers jours et 4 sur les 7 derniers jours, avec un uptime moyen de 72 % sur 30 jours. Le groupe maintient un site de fuite principal et onze serveurs de fichiers en .onion, dont plusieurs sont signalés comme indisponibles. La publication la plus récente, découverte le 3 octobre 2026 à 01:32, concerne « Paessolucoes », décrite comme l'entreprise brésilienne Paes Soluções (logiciels métier, hébergement, sauvegarde cloud, VPS, support technique, basée à Campo Mourão, Paraná). D'autres victimes sont listées : Ressources Si (exploitation de salles de cinéma), Scenario Management / SMCare (services sociaux et soins résidentiels au Royaume-Uni), Asesoría FAR (gestion immobilière et conseil à Barcelone) et Universität Hamburg (université allemande de plus de 42 000 étudiants). Le groupe expose également un identifiant Tox et des règles d'affiliation pour ses affiliés.

---

### Analyse opérationnelle

Le groupe Panzer affiche une activité soutenue (18 publications en 30 jours) et cible des organisations de tailles et de secteurs variés, y compris des prestataires IT et des établissements d'enseignement et de santé. Pour un SOC, la priorité est la surveillance des mentions de l'organisation et de ses fournisseurs sur les sites de fuite, ainsi que la détection des précurseurs classiques de double extorsion : exfiltration massive de données, suppression des journaux et des clichés instantanés, création de comptes privilégiés. Les infrastructures .onion listées doivent être bloquées au niveau proxy/DNS et intégrées aux règles de détection. La compromission d'un prestataire IT (comme Paes Soluções) constitue un vecteur de risque indirect majeur pour ses clients, qui doivent être identifiés et surveillés en priorité.

---

### Implications stratégiques

La cible de prestataires de services IT et d'hébergement illustre le risque de contagion de la chaîne d'approvisionnement : une compromission chez un MSP peut se propager à l'ensemble de son portefeuille clients. Le ciblage simultané d'acteurs de santé, d'éducation et de services sociaux souligne la persistance de l'exposition des secteurs à forte criticité sociale et à faibles budgets de sécurité. La dimension internationale (Brésil, Espagne, Royaume-Uni, Allemagne) confirme que le modèle de la double extorsion reste rentable et peu contraint par les frontières, ce qui impose une préparation de crise incluant communication, juridique et assurance.

---

### Recommandations

* Surveiller en continu les sites de fuite pour détecter toute mention de l'organisation ou de ses fournisseurs.
* Bloquer les infrastructures .onion identifiées au niveau proxy, DNS et pare-feu.
* Renforcer la détection sur la suppression des journaux et des clichés instantanés.
* Auditer les accès et la posture de sécurité des prestataires IT critiques.
* Valider l'existence de sauvegardes hors ligne immuables et tester leur restauration.
* Préparer un plan de communication de crise et vérifier les obligations de notification légale.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Tenir à jour une cartographie des actifs exposés et des dépendances fournisseurs (MSP, hébergeurs, éditeurs).
* Valider l'existence de sauvegardes hors ligne immuables et tester les procédures de restauration.
* Préparer une cellule de crise incluant communication, juridique, direction et assurance cyber.
* Vérifier les clauses contractuelles avec les prestataires IT et les obligations de notification RGPD.

#### Phase 2 — Détection et analyse

* Surveiller les accès aux URL .onion du groupe Panzer et les mentions de l'organisation sur les sites de fuite.
* Détecter les volumes anormaux de lecture/écriture de fichiers et les renommages massifs d'extensions.
* Alerter sur la suppression des clichés instantanés (shadow copies) et des journaux d'événements.
* Corréler les connexions RDP/VPN inhabituelles et les créations de comptes privilégiés hors fenêtre de changement.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments réseau affectés et révoquer les sessions et jetons d'authentification.
* Désactiver les comptes compromis et réinitialiser les secrets (mots de passe, clés API, certificats).
* Couper les accès sortants vers les infrastructures de l'attaquant et bloquer les IOC connus.
* Préserver les preuves (mémoire, disques, journaux) avant toute remédiation destructive.

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes saines vérifiées et reconstruire les systèmes compromis.
* Réaliser un retour d'expérience formel et mettre à jour le plan de réponse à incident.
* Notifier les autorités et les personnes concernées conformément aux obligations légales.
* Renforcer la segmentation, le MFA et la gestion des privilèges sur les points d'entrée identifiés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts de l'acteur Panzer sur l'ensemble du parc (binaires, scripts, tâches planifiées).
* Chasser les mouvements latéraux via SMB, WMI, PsExec et les outils d'administration détournés.
* Analyser les journaux d'authentification pour détecter des accès persistants non détectés.
* Vérifier l'absence de balises de fuite ou de canaux de communication résiduels avec l'attaquant.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxp://pnzruro7syvwvefx5mpo2fhzi4jftgquynsqf3vy5x3no57yp2iz4nyd[.]onion/` | High |
| URL | `hxxp://34enzhp4pkfrj5bnmede23wk2io2a44nj23ldwvv3stkaewurup7svad[.]onion/` | High |
| URL | `hxxp://tvhm7xw756yscfixmoyr2aymgu4oan66ospp44vcykvgxmgyq3ua2vyd[.]onion/` | High |
| URL | `hxxp://ixxrzs3zo57qhbscszen2nvx6hgav5zrx6tjs7lq6unsphwcadeadlid[.]onion/` | High |
| URL | `hxxp://qxstd6r6zkzgoolpdqsdxf4lq6rhukgpngwrgbejyyioqy2kwbkxpiyd[.]onion/` | High |
| URL | `hxxp://uchhaxue34fz6r2nyrvatxynponoe7wy6ffhwwigpfbz5zgz24w5b6id[.]onion/` | High |
| URL | `hxxp://vqyux3rgt3ips2kecakobstj4ht2bmfjvpqdignb6zpjpstkmbun5fqd[.]onion/` | High |
| URL | `hxxp://sl3iwbho7zdqjc3phm24pcd2xnko3nympkiplp6xthkc4775lb6nmxqd[.]onion/` | High |
| URL | `hxxp://mbqq27t4idm3im2wqtb2sziynr4gtatqbeozrrvkdy7pco4ah3roxfyd[.]onion/` | High |
| URL | `hxxp://czxzcu2smxtrbm7rj4eclskgydq5kiif4tgrvlsn2ri5rbndj5hu6wad[.]onion/` | High |
| URL | `hxxp://aket65o2xznczt5ef4xtlo46g6lv5nlebjpsjrl3ihrvq3pmysekhhyd[.]onion/` | High |
| URL | `hxxp://2v75pgpqlguqpflfjtz6iynwg3ndshjhh6vkxyldorarc6mpc5if5qqd[.]onion/` | High |
| DOMAIN | `paessolucoes[.]com[.]br` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement des données pour impact (rançongiciel) |
| **T1657** | Vol et extorsion financière via fuite de données (double extorsion) |
| **T1591** | Collecte d'informations sur les victimes pour ciblage et pression |

---

### Sources

* [https://www.ransomlook.io//group/panzer](https://www.ransomlook.io//group/panzer)


---

<div id="contexte-long-la-cloture1-rechercher-dans-la-page-built-les-cles-secretes-publiable-ok-cle-de-service-supprimer-redeployer-faire-tourner-traiter-comme-exposee-2-chaque-table-confirmer-que-la-regle-de-ligne-existe-puis-le-prouver-avec-un-second-compte-de-test-et-sans-session-en-lecture-et-en-ecriture-3-chaque-validation-obtient-une-ligne-comment-verifie-une-date-et-un-humain-nommevos-propres-applications-uniquement-pas-un-test-dintrusion-les-questions-que-personne-na-poseesappsec-infosec"></div>

## Contexte long — la clôture:1. Rechercher dans la page BUILT les clés secrètes (publiable ok ; clé de service : supprimer, redéployer, faire tourner, traiter comme exposée). 2. Chaque table : confirmer que la règle de ligne existe, puis le prouver avec un second compte de test et sans session, en lecture et en écriture. 3. Chaque validation obtient une ligne Comment-vérifié, une date et un humain nommé.Vos propres applications uniquement. Pas un test d'intrusion — les questions que personne n'a posées.#AppSec #infosec

### Résumé

Publication AppSec décrivant une méthode de clôture de revue de sécurité applicative en trois points : (1) rechercher les clés secrètes dans la page compilée déployée — les clés publiques sont acceptables, mais une clé de service doit être supprimée, l'application redéployée, la clé pivotée et considérée comme exposée ; (2) pour chaque table, confirmer l'existence de la règle de restriction de lignes (row rule), puis la prouver avec un second compte de test et sans session, en lecture comme en écriture ; (3) chaque validation doit être tracée par une ligne « How-verified », une date et un humain nommé. L'auteur précise que la démarche s'applique à ses propres applications et ne constitue pas un test d'intrusion.

---

### Analyse opérationnelle

Cette méthode fournit une checklist directement exploitable par les équipes AppSec et DevSecOps pour détecter deux classes de vulnérabilités fréquentes : l'exposition de clés de service dans les artefacts front-end et l'absence ou l'insuffisance de règles d'autorisation au niveau des lignes (RLS) dans les backends de type Supabase. L'impact concret est double : une clé de service exposée permet un contournement complet des contrôles d'accès applicatifs, et une règle de lignes absente ou mal configurée permet la lecture ou l'écriture non authentifiée de données. La vérification par un second compte et sans session est essentielle car elle reproduit la position d'un attaquant non authentifié. La traçabilité nominative et datée des vérifications facilite l'audit et la responsabilisation.

---

### Implications stratégiques

La généralisation des backends as-a-service (BaaS) déplace la surface d'attaque vers la configuration d'autorisation, souvent déléguée aux développeurs sans expertise sécurité dédiée. Les erreurs de configuration de règles d'accès aux données deviennent une cause majeure de fuite de données, avec des conséquences réglementaires directes (RGPD, notifications). L'adoption de revues de sécurité systématiques et tracées avant mise en production constitue un levier de réduction de risque à faible coût, à intégrer dans les processus CI/CD et les exigences contractuelles avec les prestataires de développement.

---

### Recommandations

* Rechercher systématiquement les clés de service dans les bundles front-end et les dépôts de code.
* Pivoter immédiatement toute clé de service exposée et la traiter comme compromise.
* Vérifier chaque règle d'accès aux tables avec un second compte et sans session, en lecture et en écriture.
* Tracer chaque validation par une ligne « How-verified », une date et un responsable nommé.
* Intégrer ces contrôles dans le pipeline CI/CD avant toute mise en production.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les applications et les clés exposées côté client (publishable vs service key).
* Définir une politique de gestion des secrets : rotation, stockage, séparation des environnements.
* Établir une procédure de revue systématique des règles d'accès aux tables (RLS) avant mise en production.

#### Phase 2 — Détection et analyse

* Rechercher les clés de service dans les bundles front-end, dépôts Git et journaux de build.
* Tester chaque table avec un second compte de test et sans session pour vérifier les règles de lecture/écriture.
* Surveiller les accès anormaux aux API backend et les requêtes massives non authentifiées.

#### Phase 3 — Confinement, éradication et récupération

* Retirer immédiatement toute clé de service exposée, redéployer et procéder à la rotation.
* Considérer la clé comme compromise et révoquer les sessions associées.
* Restreindre temporairement les accès aux tables non correctement protégées.

#### Phase 4 — Activités post-incident

* Documenter chaque vérification avec une ligne « How-verified », une date et un responsable nommé.
* Mettre à jour les procédures de revue de code et de déploiement pour intégrer les contrôles d'accès.
* Former les développeurs à la gestion des secrets et aux modèles d'autorisation côté base de données.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des accès non authentifiés ou avec des comptes de test dans les journaux d'API.
* Analyser les requêtes inhabituelles sur les tables sensibles (volumétrie, horaires, sources).
* Vérifier l'absence d'autres secrets exposés dans les artefacts de build et les dépôts publics.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552.001** | Identifiants non sécurisés dans les fichiers (clés de service exposées) |
| **T1078** | Utilisation de comptes valides pour accéder aux données |

---

### Sources

* [https://mastodon.social/@BigG_TheCreator/117373796394798619](https://mastodon.social/@BigG_TheCreator/117373796394798619)


---

<div id="infosec-malware-antivirusblog-elhackernet-usan-exclusiones-de-microsoft-defender-para-ocultar-malwarehttpsblogelhackernet202610usan-exclusiones-de-microsoft-defenderhtmlm1"></div>

## #infosec #malware #antivirusBlog elhacker.NET: Usan exclusiones de Microsoft Defender para ocultar malwarehttps://blog.elhacker.net/2026/10/usan-exclusiones-de-microsoft-defender.html?m=1

### Résumé

Des attaquants exploitent les exclusions de Microsoft Defender Antivirus pour empêcher la détection de fichiers malveillants lors des analyses de sécurité routinières. Plutôt que de désactiver complètement la protection, ils maintiennent l'antivirus actif tout en créant des brèches sur des dossiers spécifiques et des types de fichiers sélectionnés. Cette technique d'évasion est établie et requiert des privilèges administrateur ou supérieurs, ce qui en fait une étape postérieure à l'obtention d'un contrôle suffisant. Des rapports indépendants sur de faux installateurs de Claude pour bureau montrent comment des téléchargements malveillants peuvent entraîner des modifications d'exclusions protégeant un malware d'accès distant. Les chercheurs de Huntress ont identifié un usage plus large de cette technique, dans un rapport du 30 septembre qui relie ce comportement à GootKit en 2019, WhisperGate en 2022 et Muddled Libra en 2024. Defender prend en charge les exclusions pour les chemins, extensions de fichiers, processus et adresses IP ; les exclusions de chemins et d'extensions sont les plus utiles aux attaquants pour réduire la visibilité. Les modifications peuvent être réalisées via PowerShell, WMI, les stratégies de groupe ou des changements directs dans le registre. L'édition directe de l'emplacement de registre des exclusions propres à Defender est restreinte, mais les attaquants peuvent modifier l'emplacement correspondant de la stratégie de groupe.

---

### Analyse opérationnelle

Cette technique constitue une évasion de défense de type T1562.001 qui neutralise partiellement l'EDR/antivirus sans déclencher les alertes liées à la désactivation complète de la protection. Pour un SOC, la détection doit porter sur le changement de configuration lui-même plutôt que sur l'opération administrative : création d'exclusions via Add-MpPreference en PowerShell, appels WMI, modification de GPO ou écritures dans les clés de registre des exclusions. Il est indispensable de comparer les exclusions locales et celles gérées centralement, car les deux sources coexistent et peuvent masquer des ajouts malveillants. Les exclusions de répertoires entiers ou d'extensions sont particulièrement dangereuses car elles créent des zones de non-détection persistantes. La réponse doit inclure la suppression des exclusions non autorisées, une analyse complète et la révocation des comptes ayant effectué les modifications.

---

### Implications stratégiques

Le détournement d'un mécanisme de sécurité légitime illustre une tendance de fond : les attaquants privilégient la discrétion à la désactivation brutale, ce qui allonge le temps de présence et augmente l'impact des intrusions. La récurrence de cette technique sur plusieurs années et plusieurs familles (GootKit, WhisperGate, Muddled Libra) montre qu'il s'agit d'un TTP durable et non d'une mode. Les organisations doivent gouverner les exclusions comme un actif de sécurité critique, avec inventaire, validation et surveillance, sous peine de voir leurs investissements en détection contournés par une simple modification de configuration.

---

### Recommandations

* Inventorier et versionner toutes les exclusions Defender légitimes de l'environnement.
* Restreindre la modification des exclusions aux seuls administrateurs de sécurité.
* Alerter sur toute modification d'exclusion via PowerShell, WMI, GPO ou registre.
* Comparer régulièrement les exclusions locales et celles appliquées par stratégie de groupe.
* Supprimer immédiatement toute exclusion non autorisée et lancer une analyse complète.
* Surveiller les faux installateurs de logiciels légitimes comme vecteur de modification d'exclusions.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Établir une ligne de base des exclusions Defender légitimes (chemins, extensions, processus, IP) et la versionner.
* Restreindre les droits de modification des exclusions aux seuls administrateurs de sécurité.
* Activer la journalisation centralisée des modifications de configuration Defender et des GPO.

#### Phase 2 — Détection et analyse

* Alerter sur toute création ou modification d'exclusion Defender via PowerShell, WMI, GPO ou registre.
* Surveiller les exclusions portant sur des répertoires de dépôt temporaire ou des extensions inhabituelles.
* Corréler les modifications d'exclusion avec l'exécution de binaires non signés ou d'outils d'accès distant.
* Détecter les écritures dans les emplacements de registre des exclusions Defender et de la stratégie de groupe.

#### Phase 3 — Confinement, éradication et récupération

* Supprimer immédiatement les exclusions non autorisées et relancer une analyse complète.
* Isoler les hôtes concernés et révoquer les comptes ayant effectué les modifications.
* Bloquer les binaires et chemins identifiés comme protégés par les exclusions malveillantes.

#### Phase 4 — Activités post-incident

* Auditer l'ensemble du parc pour détecter d'autres exclusions non légitimes.
* Renforcer le contrôle des privilèges administratifs et la surveillance des GPO.
* Mettre à jour les procédures de durcissement des solutions EDR/antivirus et documenter les exclusions autorisées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les commandes PowerShell et WMI liées à Add-MpPreference et aux exclusions Defender.
* Chasser les modifications récentes de GPO et de registre liées aux paramètres antivirus.
* Rechercher les outils d'accès distant et les binaires déposés dans les répertoires exclus.
* Corréler les exclusions avec les alertes historiques de GootKit, WhisperGate et Muddled Libra.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1562.001** | Altération des défenses : désactivation ou modification des outils de sécurité |
| **T1059.001** | Exécution via PowerShell pour modifier les exclusions |
| **T1047** | Utilisation de WMI pour manipuler la configuration de sécurité |
| **T1112** | Modification du registre pour altérer les exclusions Defender |
| **T1484.001** | Modification de la stratégie de groupe (GPO) pour contourner les contrôles |

---

### Sources

* [https://blog.elhacker.net/2026/10/usan-exclusiones-de-microsoft-defender.html?m=1](https://blog.elhacker.net/2026/10/usan-exclusiones-de-microsoft-defender.html?m=1)


---

<div id="les-frappes-iraniennes-sur-les-centres-de-donnees-damazon-ont-cause-une-perte-permanente-de-donnees-clients"></div>

## Les frappes iraniennes sur les centres de données d'Amazon ont causé une perte permanente de données clients

### Résumé

Six mois après des frappes de drones iraniens ayant mis hors service plusieurs centres de données Amazon, l'entreprise américaine a reconnu la perte définitive de données clients hébergées à Bahreïn et aux Émirats arabes unis. Selon une mise à jour du tableau de bord AWS publiée le 15 septembre, AWS n'a pas pu restaurer l'accès aux ressources et données hébergées dans certains centres de données endommagés. Les données ont été irrémédiablement perdues dans l'une des trois zones de disponibilité de la région des Émirats arabes unis, la zone mec1-az2. La destruction est plus étendue à Bahreïn, où Amazon indique ne pas avoir pu restaurer l'accès aux ressources et données dans les trois zones de disponibilité. AWS déclare que les dommages ont dépassé ce que ses services régionaux et multi-AZ sont conçus pour supporter. Les premières frappes ont eu lieu le 1er mars, au début de la guerre déclenchée par les attaques américano-israéliennes contre l'Iran le 28 février. Une seconde frappe a visé les centres de données de Bahreïn le 1er avril, et le 24 juillet le Corps des Gardiens de la révolution islamique a lancé une nouvelle attaque de missiles ciblant une structure restante d'Amazon à Bahreïn, confirmée par imagerie satellite. AWS a suspendu la facturation des clients dans les régions affectées et aurait émis 150 millions de dollars de crédits clients.

---

### Analyse opérationnelle

Cet événement démontre qu'un fournisseur cloud hyperscaler ne peut pas garantir la résilience face à une destruction physique délibérée de plusieurs zones de disponibilité simultanément. Pour les équipes IT et continuité d'activité, la leçon opérationnelle est que la redondance multi-AZ dans une même région géographique ne protège pas contre un risque militaire ou géopolitique localisé. Les plans de reprise doivent intégrer des sauvegardes hors région, idéalement hors fournisseur, et des procédures de bascule testées. La perte définitive de données impose également une revue des obligations de notification réglementaire et contractuelle, ainsi qu'une réévaluation des SLA et des clauses de responsabilité avec le fournisseur.

---

### Implications stratégiques

L'attaque illustre la convergence entre conflit armé et infrastructure numérique : les centres de données deviennent des cibles militaires légitimes aux yeux des belligérants, avec des conséquences directes sur les données de clients privés. Cela remet en cause le postulat de résilience géographique des stratégies cloud et pousse à une diversification multi-cloud et multi-région, avec un coût significatif. Le conflit s'est par ailleurs élargi en crise énergétique mondiale du fait des attaques sur le détroit d'Ormuz et le détroit de Bab al-Mandeb, renforçant l'intérêt pour les énergies renouvelables. Pour les décideurs, la localisation des données et des infrastructures devient un critère de risque géopolitique à part entière.

---

### Recommandations

* Mettre en place des sauvegardes hors région et hors fournisseur cloud, testées régulièrement.
* Tester les procédures de bascule multi-région et multi-cloud au moins une fois par an.
* Intégrer le risque géopolitique et physique dans les analyses d'impact métier.
* Revoir les SLA et clauses de responsabilité avec les fournisseurs cloud.
* Préparer les obligations de notification en cas de perte définitive de données personnelles.
* Documenter les données critiques et leur localisation pour prioriser les plans de continuité.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les dépendances aux régions cloud et identifier les zones de disponibilité critiques.
* Mettre en place des sauvegardes hors région et hors fournisseur, testées régulièrement.
* Intégrer le risque géopolitique et physique dans les analyses d'impact métier (BIA).
* Définir des procédures de bascule multi-région et multi-cloud documentées et testées.

#### Phase 2 — Détection et analyse

* Surveiller les tableaux de bord de disponibilité des fournisseurs cloud et les notifications d'incident.
* Détecter les pertes d'accès aux ressources et les échecs de restauration dans les régions affectées.
* Alerter sur les anomalies de réplication et de sauvegarde inter-régions.

#### Phase 3 — Confinement, éradication et récupération

* Migrer les charges de travail vers des régions ou fournisseurs non affectés.
* Activer les plans de continuité et basculer sur les sauvegardes distantes.
* Suspendre les dépendances non critiques et prioriser les services essentiels.

#### Phase 4 — Activités post-incident

* Documenter les données définitivement perdues et évaluer les obligations de notification.
* Réviser la stratégie de résilience : redondance géographique, fournisseurs multiples, sauvegardes hors ligne.
* Négocier les compensations et crédits avec le fournisseur cloud et revoir les SLA.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les accès résiduels ou les ressources orphelines dans les régions affectées.
* Vérifier l'intégrité des données restaurées et détecter toute corruption ou altération.
* Analyser les journaux d'accès pour détecter d'éventuelles activités malveillantes opportunistes pendant la crise.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1485** | Destruction de données par dommage physique à l'infrastructure |
| **T1561** | Effacement de disque / destruction de supports de stockage |

---

### Sources

* [https://arstechnica.com/gadgets/2026/09/iran-strikes-on-amazon-data-centers-caused-permanent-loss-of-customer-data/](https://arstechnica.com/gadgets/2026/09/iran-strikes-on-amazon-data-centers-caused-permanent-loss-of-customer-data/)


---

<div id="possible-phishing-on-hxxpswwwrobloxcomamusers474624665347profile-analysis-at-httpsurldnaioscan6abf64bd3b77500002f12ce9-cybersecurity-phishing-infosec-urldna-scam-infosec"></div>

## Possible Phishing 🎣  on: ⚠️hxxps[:]//www[.]roblox[.]com[.]am/users/474624665347/profile  🧬 Analysis at: https://urldna.io/scan/6abf64bd3b77500002f12ce9 #cybersecurity #phishing #infosec #urldna #scam #infosec

### Résumé

Une analyse URLDNA signale une possible page d'hameçonnage hébergée à l'adresse hxxps://www[.]roblox[.]com[.]am/users/474624665347/profile. Le domaine roblox[.]com[.]am imite la marque Roblox en utilisant le domaine de premier niveau .am, technique classique de typosquattage visant à tromper les utilisateurs. L'URL cible une page de profil utilisateur, format fréquemment utilisé pour rediriger vers des formulaires de connexion frauduleux ou des pages de collecte d'identifiants. Aucun contenu textuel additionnel n'est fourni par la source.

---

### Analyse opérationnelle

Le domaine roblox[.]com[.]am doit être bloqué au niveau DNS, proxy et passerelle de messagerie. La structure de l'URL (chemin /users/<identifiant>/profile) imite le format légitime de la plateforme, ce qui la rend crédible pour un utilisateur non averti et facilite la collecte d'identifiants ou la redirection vers des contenus malveillants. Les équipes SOC doivent rechercher les accès historiques à ce domaine dans les journaux proxy et DNS, identifier les comptes ayant interagi avec la page et vérifier toute activité post-compromission. La détection doit s'appuyer sur la résolution de domaines typosquattant des marques grand public, particulièrement dans les environnements scolaires et familiaux où Roblox est très utilisé.

---

### Implications stratégiques

Le typosquattage de marques grand public très populaires auprès des jeunes publics reste un vecteur d'hameçonnage à fort volume et faible coût pour les attaquants. Ces campagnes ciblent souvent des utilisateurs peu formés à la sécurité, ce qui accroît le taux de succès et expose les organisations à des compromissions de comptes personnels réutilisés en contexte professionnel. La surveillance continue des domaines imitant les marques de l'écosystème numérique et la sensibilisation des utilisateurs constituent des mesures de réduction de risque à faible coût.

---

### Recommandations

* Bloquer le domaine roblox[.]com[.]am et l'URL associée sur tous les points de contrôle réseau.
* Rechercher les accès historiques au domaine dans les journaux proxy et DNS.
* Réinitialiser les identifiants des utilisateurs ayant interagi avec la page frauduleuse.
* Sensibiliser les utilisateurs aux URL usurpant des marques de jeux et de divertissement.
* Signaler le domaine frauduleux au registraire et aux autorités compétentes.
* Surveiller les nouveaux domaines typosquattant les marques populaires de l'écosystème numérique.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer le blocage des domaines typosquattés de marques grand public au niveau proxy et DNS.
* Sensibiliser les utilisateurs aux URL usurpant des services de jeux et de divertissement.
* Mettre en place une remontée rapide des URL suspectes vers l'équipe sécurité.

#### Phase 2 — Détection et analyse

* Détecter les résolutions DNS et les connexions vers des domaines imitant des marques légitimes.
* Surveiller les soumissions d'URL suspectes et les analyses de réputation.
* Alerter sur les accès à des pages de profil ou de connexion hébergées sur des domaines non officiels.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le domaine et l'URL identifiés sur l'ensemble des points de contrôle réseau.
* Réinitialiser les identifiants des utilisateurs ayant saisi leurs informations sur la page frauduleuse.
* Ajouter l'IOC aux listes de blocage et aux règles de détection.

#### Phase 4 — Activités post-incident

* Documenter la campagne et diffuser une alerte interne aux utilisateurs concernés.
* Signaler le domaine frauduleux aux autorités compétentes et au registraire.
* Renforcer les contrôles de vérification d'URL dans les passerelles de messagerie et les navigateurs.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les accès historiques au domaine typosquatté dans les journaux proxy et DNS.
* Identifier les comptes ayant interagi avec la page et vérifier les activités post-compromission.
* Rechercher d'autres domaines typosquattant la même marque dans les journaux de résolution.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://www[.]roblox[.]com[.]am/users/474624665347/profile` | Medium |
| DOMAIN | `roblox[.]com[.]am` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Hameçonnage par lien (spearphishing link) |
| **T1583.001** | Acquisition d'infrastructure : enregistrement de domaines typosquattés |

---

### Sources

* [https://urldna.io/scan/6abf64bd3b77500002f12ce9](https://urldna.io/scan/6abf64bd3b77500002f12ce9)


---

<div id="1706421468-flagged-for-mixed-malicious-activity-hosted-at-digitalocean-in-au-tracked-by-2-independent-feeds-worth-a-look-if-it-hits-your-logs-httpswwwvaltersitcomthreat-ip1706421468-threatintel-infosec"></div>

## 170.64.214.68 flagged for mixed malicious activity. Hosted at DigitalOcean in AU, tracked by 2 independent feeds. Worth a look if it hits your logs. https://www.valtersit.com/threat-ip/170.64.214.68/ #ThreatIntel #InfoSec

### Résumé

L'adresse IP 170.64.214[.]68 est signalée pour une activité malveillante mixte. Elle est hébergée chez DigitalOcean en Australie et référencée par deux feeds de threat intelligence indépendants. La source recommande de vérifier sa présence dans les journaux de sécurité.

---

### Analyse opérationnelle

Cette IP constitue un indicateur de compromission de fiabilité moyenne à intégrer dans les dispositifs de détection. Les équipes SOC doivent rechercher toute communication avec cette adresse dans les logs pare-feu, proxy, DNS et EDR. Une activité confirmée justifie un blocage périmétrique et une investigation des hôtes concernés. L'hébergement chez un fournisseur cloud majeur (DigitalOcean) facilite la rotation rapide de l'infrastructure, ce qui impose une surveillance continue plutôt qu'un blocage ponctuel.

---

### Implications stratégiques

L'usage d'hébergeurs cloud légitimes pour héberger des infrastructures malveillantes brouille la frontière entre trafic légitime et hostile. Les organisations doivent intégrer la réputation IP dynamique dans leur posture de défense et ne pas se reposer uniquement sur des listes statiques. La mention de deux feeds indépendants renforce la crédibilité de l'indicateur et plaide pour une consommation multi-sources de la threat intelligence.

---

### Recommandations

* Ajouter 170.64.214[.]68 aux listes de surveillance et de blocage selon le niveau de risque accepté.
* Vérifier la présence de l'IP dans les journaux des 30 derniers jours.
* Enrichir les alertes SIEM avec les feeds de réputation IP.
* Surveiller les connexions sortantes vers DigitalOcean en région AU.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer la liste de réputation IP (ValtersIT et feeds partenaires) dans les pare-feu, proxies et SIEM pour enrichissement automatique.
* Vérifier que la journalisation NetFlow/pare-feu et DNS est active et conservée au moins 90 jours.
* Définir une procédure de blocage temporaire des IP signalées par au moins deux feeds indépendants.

#### Phase 2 — Détection et analyse

* Rechercher l'IP 170.64.214[.]68 dans les logs pare-feu, proxy, DNS et EDR sur les 30 derniers jours.
* Corréler avec les connexions sortantes inhabituelles vers des hébergeurs cloud (DigitalOcean, région AU).
* Alerter sur toute session authentifiée ou téléchargement provenant de cette IP.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'IP au niveau périmétrique et sur les points de sortie si activité malveillante confirmée.
* Isoler les hôtes ayant communiqué avec l'IP et préserver les artefacts (mémoire, journaux).
* Révoquer les sessions et identifiants potentiellement compromis via cette infrastructure.

#### Phase 4 — Activités post-incident

* Documenter la chronologie des connexions et l'impact éventuel.
* Mettre à jour les règles de détection et la liste de blocage selon les retours d'expérience.
* Notifier les parties prenantes si des données ont été exfiltrées.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les comportements de balayage, brute force ou C2 associés à des IP d'hébergeurs cloud.
* Rechercher d'autres IP du même ASN/réseau DigitalOcean dans les logs.
* Surveiller la réapparition de l'IP sous d'autres adresses du même bloc.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `170.64.214[.]68` | Medium |
| DOMAIN | `valtersit[.]com` | Low |

---

### Sources

* [https://www.valtersit.com/threat-ip/170.64.214.68/](https://www.valtersit.com/threat-ip/170.64.214.68/)


---

<div id="mat-bao-corporation-par-rhysida"></div>

## Mat Bao Corporation Par rhysida

### Résumé

Le groupe rançongiciel Rhysida revendique la compromission de Mat Bao Corporation sur son site de fuite. L'entrée indique un statut de publication partiel (5/7) sur le portail du groupe.

---

### Analyse opérationnelle

La revendication sur un site de fuite implique généralement une exfiltration de données préalable au chiffrement. Les équipes doivent considérer les données de l'organisation comme potentiellement exposées et prioriser la recherche d'exfiltration, la rotation des secrets et la vérification des sauvegardes. La détection doit porter sur les accès distants, les mouvements latéraux et les outils de chiffrement.

---

### Implications stratégiques

Rhysida cible des secteurs variés avec une logique de double extorsion, augmentant le risque réputationnel et juridique. Pour les entreprises technologiques, la compromission peut exposer des données clients et des secrets d'infrastructure, avec un effet domino sur leurs propres clients. La pression à la négociation doit être contrebalancée par une préparation juridique et une stratégie de non-paiement.

---

### Recommandations

* Vérifier l'authenticité de la revendication et l'étendue des données exposées.
* Renforcer la surveillance des accès distants et des comptes à privilèges.
* Tester la restauration des sauvegardes hors ligne.
* Préparer une communication de crise et une notification réglementaire si nécessaire.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les actifs critiques et les sauvegardes hors ligne pour la société ciblée.
* Vérifier la segmentation réseau et l'authentification multifacteur sur les accès distants.
* Préparer un plan de communication de crise et un contact juridique/rançongiciel.

#### Phase 2 — Détection et analyse

* Surveiller les fuites publiées sur le site de Rhysida et les canaux associés.
* Détecter les signes d'exfiltration massive et de chiffrement (volumes anormaux, extensions renommées).
* Alerter sur les connexions RDP/VPN suspectes et les créations de comptes non autorisées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les segments compromis et couper les accès distants.
* Révoquer les identifiants et sessions actives, réinitialiser les comptes à privilèges.
* Préserver les preuves et ne pas payer la rançon sans analyse juridique et décisionnelle.

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes saines vérifiées et reconstruire les systèmes touchés.
* Notifier les autorités et les clients si des données personnelles sont exposées.
* Réaliser un retour d'expérience et durcir les accès et la détection.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les TTP de Rhysida : persistance, mouvement latéral, outils de chiffrement.
* Analyser les journaux d'exfiltration et les connexions vers des services de stockage externes.
* Surveiller les réutilisations d'infrastructure et les nouvelles victimes du groupe.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1657** | Financial Theft (extorsion par rançon) |

---

### Sources

* [https://www.ransomlook.io//group/rhysida](https://www.ransomlook.io//group/rhysida)


---

<div id="thai-lion-air-par-qilin"></div>

## Thai Lion Air Par qilin

### Résumé

Le groupe rançongiciel Qilin, opérant en modèle Ransomware-as-a-Service, revendique la compromission de Thai Lion Air sur son site de fuite. L'entrée indique un statut de publication partiel (4/640).

---

### Analyse opérationnelle

La revendication concerne un acteur du transport aérien, secteur à forte criticité opérationnelle. Les équipes doivent évaluer l'exposition des données passagers et des systèmes de réservation, et vérifier l'intégrité des sauvegardes. La détection doit cibler les accès distants, les mouvements latéraux et les exfiltrations massives.

---

### Implications stratégiques

Le modèle RaaS de Qilin abaisse la barrière technique et multiplie les attaques. Une compromission dans l'aviation peut perturber les opérations, exposer des données personnelles de voyageurs et déclencher des obligations réglementaires. La dépendance aux systèmes tiers et partenaires élargit la surface d'attaque et impose une gestion rigoureuse des risques fournisseurs.

---

### Recommandations

* Évaluer l'étendue des données exposées et les obligations de notification.
* Renforcer la segmentation entre systèmes IT et opérationnels.
* Vérifier les sauvegardes et tester les procédures de restauration.
* Surveiller les accès tiers et partenaires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les systèmes critiques de réservation, opérations et service client.
* Vérifier les sauvegardes isolées et les plans de continuité pour les opérations aériennes.
* Mettre en place une surveillance renforcée des accès tiers et partenaires.

#### Phase 2 — Détection et analyse

* Surveiller les publications du groupe Qilin et les fuites de données associées.
* Détecter les accès anormaux aux systèmes de réservation et aux bases clients.
* Alerter sur les tentatives d'exfiltration et les connexions C2.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes affectés sans interrompre les opérations de vol critiques.
* Révoquer les accès compromis et segmenter les réseaux IT/OT.
* Préserver les preuves et engager une cellule de crise.

#### Phase 4 — Activités post-incident

* Restaurer les services depuis des sauvegardes vérifiées.
* Notifier les autorités aériennes et les clients concernés.
* Renforcer la détection et la résilience des systèmes critiques.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les TTP de Qilin (RaaS) : accès initial, persistance, exfiltration.
* Analyser les journaux des partenaires et fournisseurs tiers.
* Surveiller les nouvelles victimes et l'évolution des outils du groupe.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1657** | Financial Theft (extorsion par rançon) |

---

### Sources

* [https://www.ransomlook.io//group/qilin](https://www.ransomlook.io//group/qilin)


---

<div id="la-ville-de-vicksburg-mississippi-eteint-ses-ordinateurs-apres-une-cyberattaque"></div>

## La ville de Vicksburg, Mississippi, éteint ses ordinateurs après une cyberattaque

### Résumé

La ville de Vicksburg, dans le Mississippi, a mis hors ligne ses systèmes informatiques après une attaque par rançongiciel. Le maire Willis Thompson a indiqué que les opérations Internet ont été coupées par mesure de protection. Les paiements en personne des services publics peuvent être retardés, mais la ville précise qu'aucune pénalité ni coupure de service n'aura lieu pendant l'interruption. Le bureau de l'eau et du gaz dessert plus de 10 000 comptes. Aucun groupe n'a revendiqué l'attaque et il n'est pas confirmé qu'il s'agisse d'un chiffrement effectif ou d'une simple demande de rançon.

---

### Analyse opérationnelle

L'incident illustre la vulnérabilité des collectivités locales face aux rançongiciels. La déconnexion d'Internet est une mesure de confinement classique mais qui perturbe les services aux citoyens. Les équipes doivent vérifier l'intégrité des sauvegardes, analyser les journaux d'accès distants et rechercher les mouvements latéraux. La continuité des services essentiels (eau, gaz, urgences) doit être maintenue via des procédures manuelles.

---

### Implications stratégiques

Les attaques contre les collectivités locales ont un impact direct sur les citoyens et la confiance publique. Le manque de moyens et de personnel cyber dans le secteur public en fait une cible privilégiée. La clarification entre chiffrement réel et simple demande de rançon est essentielle pour calibrer la réponse et la communication. Ces incidents renforcent la nécessité d'investissements en résilience et en cybersécurité pour les infrastructures municipales.

---

### Recommandations

* Vérifier l'intégrité des sauvegardes et préparer la restauration.
* Analyser les journaux d'accès distants et les comptes à privilèges.
* Maintenir les services essentiels via des procédures manuelles.
* Communiquer de manière transparente avec les citoyens et les autorités.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les systèmes critiques (paiement des services publics, réponse d'urgence).
* Établir des procédures de continuité pour les paiements en présentiel et les services essentiels.
* Vérifier les sauvegardes hors ligne et les plans de communication publique.

#### Phase 2 — Détection et analyse

* Surveiller les signes de chiffrement, de déconnexion réseau et d'arrêt de services.
* Analyser les journaux d'accès distants et les comptes à privilèges.
* Détecter les tentatives d'exfiltration et les connexions C2.

#### Phase 3 — Confinement, éradication et récupération

* Déconnecter les systèmes affectés d'Internet comme mesure de protection.
* Isoler les segments compromis et préserver les preuves.
* Maintenir les services essentiels (eau, gaz, urgences) via des procédures manuelles.

#### Phase 4 — Activités post-incident

* Restaurer les systèmes depuis des sauvegardes saines.
* Communiquer publiquement sur l'absence de pénalités pendant l'interruption.
* Notifier les autorités et réaliser un retour d'expérience.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les TTP de ransomware : persistance, mouvement latéral, exfiltration.
* Analyser les journaux des 30 derniers jours pour identifier le vecteur initial.
* Surveiller les revendications sur les sites de fuite.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1489** | Service Stop |

---

### Sources

* [https://databreaches.net/2026/10/02/city-of-vicksburg-mississippi-shuts-down-computers-after-cyberattack/](https://databreaches.net/2026/10/02/city-of-vicksburg-mississippi-shuts-down-computers-after-cyberattack/)


---

<div id="plus-de-543-000-identifiants-valides-exposes-dans-des-depots-github-publiqueshttpswwwbleepingcomputercomnewssecurityover-543-000-valid-credentials-exposed-in-public-github-repositoriescybersecurity-databreach"></div>

## Plus de 543 000 identifiants valides exposés dans des dépôts #GitHub publiqueshttps://www.bleepingcomputer.com/news/security/over-543-000-valid-credentials-exposed-in-public-github-repositories/#cybersecurity #DataBreach

### Résumé

Plus de 543 000 identifiants valides ont été exposés dans des dépôts GitHub publics, selon BleepingComputer. Ces credentials, encore actifs, représentent un risque direct de compromission pour les services et infrastructures associés.

---

### Analyse opérationnelle

L'exposition de credentials valides dans des dépôts publics constitue une porte d'entrée immédiate pour les attaquants. Les équipes doivent scanner leurs dépôts, révoquer et faire tourner les secrets exposés, et auditer les accès effectués avec ces identifiants. La détection doit porter sur les connexions inhabituelles aux services cloud et API, et sur les tentatives d'authentification depuis des IP inconnues.

---

### Implications stratégiques

La fuite de secrets dans le code source est une cause majeure de compromission, souvent sous-estimée. Elle expose les organisations à des accès non autorisés, des vols de données et des coûts de remédiation élevés. La généralisation de l'IA et de l'automatisation dans le développement accentue le risque si les secrets ne sont pas gérés de manière centralisée. Une gouvernance stricte des secrets et une culture DevSecOps sont indispensables.

---

### Recommandations

* Scanner tous les dépôts à la recherche de secrets exposés.
* Révoquer et faire tourner immédiatement les credentials compromis.
* Adopter un coffre-fort de secrets et une politique de rotation.
* Auditer les accès effectués avec les identifiants exposés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une analyse automatisée des dépôts GitHub pour détecter les secrets exposés.
* Définir une politique de gestion des secrets (coffres-forts, rotation, moindre privilège).
* Former les développeurs aux risques d'exposition de credentials dans le code.

#### Phase 2 — Détection et analyse

* Scanner les dépôts publics et privés à la recherche de clés API, tokens et mots de passe.
* Surveiller les alertes de fuite de secrets et les accès anormaux aux services cloud.
* Corréler les credentials exposés avec les journaux d'authentification.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les credentials exposés et faire tourner les secrets.
* Retirer les secrets des dépôts et purger l'historique Git si nécessaire.
* Restreindre les permissions des comptes concernés.

#### Phase 4 — Activités post-incident

* Auditer les accès effectués avec les credentials compromis.
* Renforcer les politiques de gestion des secrets et la revue de code.
* Notifier les parties prenantes si des données ont été accédées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les utilisations malveillantes des credentials exposés dans les journaux cloud.
* Surveiller les dépôts GitHub pour de nouvelles expositions.
* Analyser les patterns d'accès suspects depuis des IP inconnues.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552.001** | Unsecured Credentials: Credentials In Files |
| **T1213.003** | Data from Information Repositories: Code Repositories |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/over-543-000-valid-credentials-exposed-in-public-github-repositories/](https://www.bleepingcomputer.com/news/security/over-543-000-valid-credentials-exposed-in-public-github-repositories/)


---

<div id="des-domaines-de-remplacement-utilises-par-349-competences-dagents-ia-detectes-redirigeant-vers-des-arnaques"></div>

## Des domaines de remplacement utilisés par 349 compétences d'agents IA détectés redirigeant vers des arnaques

### Résumé

Des chercheurs de Manifold Security ont constaté que les domaines placeholder yoursite.com et your-domain.com, utilisés dans la documentation logicielle, apparaissent dans environ 359 000 fichiers GitHub et sont cités par 349 skills d'agents IA. Contrairement à example.com, ces domaines ne sont pas réservés par l'IANA et peuvent être enregistrés par n'importe qui. Les chercheurs ont testé les deux domaines sur 24 sessions de navigation réelles : vingt visites ont abouti à des pages de parking ou des publicités, une a rencontré un challenge Cloudflare, une a échoué et deux ont atteint des pages de scam. Ces pages frauduleuses n'ont été observées que lors des tests sous macOS ; aucune des huit sessions Windows ou Linux n'a atteint de scam. Une visite macOS sur your-domain.com a affiché un faux avertissement « MacOS Security Center » prétendant détecter quatre virus et promouvant un renouvellement contrefait de McAfee à -55 %.

---

### Analyse opérationnelle

Le vecteur ne repose pas sur une compromission de code mais sur l'exploitation de références documentaires obsolètes : tout domaine placeholder non réservé cité dans un dépôt ou un skill d'agent IA peut être enregistré par un attaquant et servir de canal de redirection frauduleuse. Pour un SOC, cela implique de surveiller les résolutions DNS vers ces domaines depuis les postes de travail, en particulier macOS, et de détecter les redirections vers de fausses interfaces de sécurité. Le cloaking observé (contenu servi uniquement sur macOS) complique la détection basée sur des sandbox Linux/Windows et impose des tests multi-OS. La surface d'attaque s'étend aux chaînes d'outillage IA : les skills d'agents IA réutilisant des exemples de documentation deviennent des vecteurs de distribution de fraude sans modification de code.

---

### Implications stratégiques

Cette affaire illustre une nouvelle forme de risque de supply chain documentaire : la dette technique des exemples de code et des skills tiers se transforme en canal de fraude monétisable. Les organisations qui déploient des agents IA et des intégrations automatisées doivent considérer la validation des références externes comme un contrôle de sécurité à part entière. À l'échelle sectorielle, la confiance dans les écosystèmes de skills d'agents IA est fragilisée, ce qui pourrait accélérer les exigences de curation et de signature des composants tiers.

---

### Recommandations

* Interdire l'usage de domaines non réservés par l'IANA dans toute documentation, exemple de code ou skill d'agent IA.
* Bloquer au niveau DNS et proxy les domaines placeholder connus et surveiller leur enregistrement.
* Auditer les dépôts internes et les skills d'agents IA à la recherche de références à yoursite[.]com et your-domain[.]com.
* Tester les redirections suspectes sur plusieurs systèmes d'exploitation pour contourner le cloaking.
* Sensibiliser les développeurs aux risques liés à la réutilisation de snippets et de composants tiers non vérifiés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser dans les dépôts de code, la documentation interne et les skills d'agents IA toutes les références aux domaines placeholder non réservés (yoursite[.]com, your-domain[.]com, etc.).
* Établir une politique interne interdisant l'usage de domaines non réservés par l'IANA dans les exemples et la documentation ; imposer example.com ou des domaines de test contrôlés.
* Intégrer les domaines placeholder connus dans les listes de blocage DNS/proxy et dans les règles de filtrage des passerelles web.
* Sensibiliser les développeurs et les équipes produit à la réutilisation de snippets et de skills tiers non vérifiés.

#### Phase 2 — Détection et analyse

* Surveiller les requêtes DNS et les connexions sortantes vers yoursite[.]com et your-domain[.]com depuis les postes, en particulier macOS.
* Détecter les redirections vers des pages de faux « Security Center » ou des offres d'abonnement antivirus frauduleuses.
* Analyser les logs proxy pour identifier les comportements de cloaking (contenu servi différemment selon l'OS ou l'User-Agent).
* Auditer les skills d'agents IA installés et les fichiers de configuration référençant des domaines placeholder.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement au niveau DNS et proxy les domaines placeholder identifiés comme malveillants.
* Isoler les postes ayant atteint une page de scam et lancer une analyse antivirus/EDR complète.
* Retirer ou corriger les skills d'agents IA et les fichiers de documentation référençant les domaines compromis.
* Révoquer les identifiants ou moyens de paiement qui auraient pu être saisis sur les pages frauduleuses.

#### Phase 4 — Activités post-incident

* Documenter les sessions de navigation compromises et les indicateurs associés (URL de redirection, domaines, horodatage).
* Mettre à jour les procédures de revue de code et de validation des dépendances/skills tiers.
* Notifier les utilisateurs concernés en cas de saisie d'informations personnelles ou de paiement.
* Réévaluer périodiquement la liste des domaines placeholder non réservés et leur statut d'enregistrement.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux historiques toute résolution DNS vers des domaines placeholder non réservés.
* Corréler les accès aux pages de faux « Security Center » avec des tentatives d'installation de logiciels non autorisés.
* Chasser les patterns de cloaking dans les réponses HTTP (contenu divergent selon l'OS détecté).
* Surveiller l'enregistrement de nouveaux domaines placeholder et l'apparition de skills d'agents IA les référençant.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `yoursite[.]com` | High |
| DOMAIN | `your-domain[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1583.001** | Acquisition d'infrastructure : enregistrement de domaines non réservés cités dans la documentation et les skills d'agents IA |
| **T1189** | Compromission par navigation (drive-by) via redirection cloaked vers des pages de scam |
| **T1036** | Masquage : fausse interface « MacOS Security Center » imitant un antivirus légitime |

---

### Sources

* [https://hackread.com/placeholder-domains-ai-agent-skills-redirect-scams/](https://hackread.com/placeholder-domains-ai-agent-skills-redirect-scams/)


---

<div id="cyber-brief-26-10-september-2026"></div>

## Cyber Brief 26-10 - September 2026

### Résumé

Le CERT-EU a analysé 358 rapports open source pour son Cyber Brief de septembre 2026. Sur le plan policier et politique, la police néerlandaise a arrêté un homme dans le cadre de l'enquête sur le groupe cybercriminel ShinyHunters, et des dirigeants des principales entreprises américaines d'IA ont briefé le Conseil de sécurité de l'ONU sur les risques liés à l'IA avancée. Concernant le cyberespionnage, des militants pro-démocratie et dissidents serbes auraient été ciblés par des outils spyware, et plusieurs campagnes liées à la Chine ont été observées, notamment des campagnes de « distillation industrielle » visant des modèles américains. Sur le front cybercriminel, Google a signalé une recrudescence du LLM-jacking, avec le vol et la revente d'accès à des outils IA premium et le détournement de serveurs cloud. Côté fuites de données, l'administration de Berlin a confirmé que le groupe Rhysida a volé environ 5,79 To de données gouvernementales, et ShinyHunters a revendiqué une intrusion dans les systèmes du FBI via une prétendue zero-day Oracle PeopleSoft. Enfin, OpenAI a alerté plusieurs organisations après que des agents IA ont interagi avec leurs sites au-delà d'une navigation passive, accédant dans certains cas à des fichiers publics et non publics sans en modifier le contenu.

---

### Analyse opérationnelle

Ce brief met en évidence plusieurs vecteurs opérationnels : l'exploitation d'applications RH/ERP exposées (Oracle PeopleSoft) comme point d'entrée pour des fuites massives, le détournement de ressources cloud et d'accès à des outils IA (LLM-jacking) générant des coûts et des risques de fuite, et le ciblage par spyware mobile de populations à risque. Pour un SOC, la priorité est la surveillance des accès aux API d'IA, la détection des charges de travail cloud non autorisées, la vérification des correctifs sur les plateformes RH/ERP et la corrélation entre revendications publiques d'acteurs et télémétrie interne. L'émergence d'agents IA autonomes accédant à des fichiers non publics impose de revoir les contrôles d'accès et les périmètres de confiance accordés aux agents automatisés.

---

### Implications stratégiques

Le brief souligne une convergence entre cybercriminalité, espionnage étatique et gouvernance de l'IA. Les arrestations liées à ShinyHunters et les revendications de fuites massives illustrent la professionnalisation des groupes cybercriminels et leur capacité à cibler des institutions gouvernementales. Les campagnes de distillation de modèles et le LLM-jacking traduisent une compétition géopolitique autour de l'IA, avec des enjeux de propriété intellectuelle et de souveraineté technologique. Pour les organisations européennes, cela renforce la nécessité d'une gouvernance stricte des accès tiers, d'une conformité renforcée (NIS2, RGPD) et d'une préparation aux incidents impliquant des agents IA autonomes.

---

### Recommandations

* Auditer et corriger en priorité les applications RH/ERP exposées, notamment Oracle PeopleSoft.
* Surveiller les consommations d'API d'IA et les workloads cloud pour détecter le LLM-jacking.
* Renforcer les contrôles d'accès et les périmètres accordés aux agents IA autonomes.
* Mettre en place une veille sur les revendications des groupes ShinyHunters et Rhysida et corréler avec la télémétrie interne.
* Protéger les populations à risque (société civile, journalistes, personnel politique) contre les spywares mobiles.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les actifs exposés liés aux applications RH/ERP (type Oracle PeopleSoft) et vérifier les niveaux de correctifs.
* Mettre en place une surveillance renforcée des accès aux services d'IA et des consommations cloud anormales (LLM-jacking).
* Établir une procédure de notification et de prise en charge des utilisateurs à risque (militants, journalistes, personnel politique).
* Vérifier les capacités de détection mobile (MDM/EDR mobile) et les alertes de type Apple Threat Notification.

#### Phase 2 — Détection et analyse

* Surveiller les indicateurs de compromission d'applications exposées et les tentatives d'exploitation de zero-day sur les plateformes RH/ERP.
* Détecter les pics d'usage d'API d'IA, les clés compromises et les charges de travail cloud non autorisées.
* Analyser les alertes de spyware sur mobiles (comportements anormaux, notifications de menace Apple).
* Corréler les revendications publiques d'acteurs cybercriminels (ShinyHunters, Rhysida) avec les journaux internes.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis et révoquer les accès et clés d'API détournés.
* Appliquer en urgence les correctifs ou mesures de contournement sur les applications vulnérables.
* Restreindre les accès tiers et les intégrations non nécessaires aux environnements sensibles.
* Activer les procédures de réponse à incident pour les fuites de données massives (notification, préservation des preuves).

#### Phase 4 — Activités post-incident

* Réaliser un retour d'expérience sur les vecteurs d'accès et les délais de détection.
* Renforcer la gouvernance des accès tiers et la gestion des secrets/API.
* Mettre à jour les plans de continuité pour les services publics impactés.
* Communiquer de manière coordonnée avec les autorités et les régulateurs concernés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces de LLM-jacking : consommation anormale d'API, comptes premium détournés, workloads cloud non planifiés.
* Chasser les indicateurs de spyware mobile sur les appareils des populations à risque.
* Rechercher des accès non autorisés aux bases RH/ERP et des exfiltrations massives.
* Surveiller les campagnes d'ingénierie sociale ciblant la société civile et les dissidents.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1496** | Détournement de ressources : LLM-jacking, vol et revente d'accès à des outils IA premium et détournement de serveurs cloud |
| **T1566** | Hameçonnage et ingénierie sociale ciblant dissidents, militants et journalistes |
| **T1409** | Accès aux données stockées sur les appareils mobiles via spyware (Pegasus, NoviSpy) |
| **T1190** | Exploitation d'une vulnérabilité présumée zero-day Oracle PeopleSoft revendiquée par ShinyHunters |
| **T1486** | Chiffrement de données à des fins d'extorsion (Rhysida) |

---

### Sources

* [https://cert.europa.eu/publications/threat-intelligence/cb26-10/](https://cert.europa.eu/publications/threat-intelligence/cb26-10/)


---

<div id="la-cisa-et-le-fbi-avertissent-les-operateurs-ot-des-piratages-de-tiers"></div>

## La CISA et le FBI avertissent les opérateurs OT des piratages de tiers

### Résumé

La CISA et le FBI ont publié un avis mettant en garde les exploitants de technologies opérationnelles (OT) contre les risques liés à l'octroi d'accès en ligne à des intégrateurs ou consultants tiers. L'avis rapporte qu'entre mars et avril 2025, des acteurs cyber malveillants étrangers ont accédé au réseau d'une société américaine de solutions d'automatisation industrielle fournissant des services d'intégration système et de conseil en ingénierie à des clients incluant des utilities électriques et des systèmes de transport. Cette société était spécialisée dans les systèmes SCADA. Les analystes techniques du FBI ont trouvé des preuves que les attaquants ont recherché les termes « customers » et « SCADA » sur le réseau, puis ont regroupé environ 800 fichiers dans des archives .zip en vue d'une exfiltration présumée. Ces fichiers contenaient des informations SCADA clients, des détails sur les équipements ICS et d'autres schémas. Selon l'avis, ces données pourraient être utilisées pour mener ultérieurement des attaques perturbatrices contre les clients de l'entreprise et perturber des services critiques.

---

### Analyse opérationnelle

L'attaque illustre l'exploitation d'une relation de confiance : l'accès légitime d'un intégrateur ICS devient un point d'entrée vers les réseaux de multiples clients d'infrastructures critiques. Pour les équipes SOC/OT, la détection doit porter sur les recherches de termes sensibles dans les journaux, la création d'archives volumineuses et les transferts sortants anormaux depuis les environnements industriels. La segmentation IT/OT, la supervision des accès distants tiers et la journalisation des sessions d'intégrateurs sont des mesures techniques prioritaires. Les schémas d'architecture, électriques et réseau constituent une cartographie complète permettant des attaques en aval, ce qui impose de traiter ces documents comme des actifs hautement sensibles.

---

### Implications stratégiques

Cet avis confirme que la chaîne d'approvisionnement OT est une cible de choix pour des acteurs étatiques sophistiqués cherchant à prépositionner des capacités d'attaque contre des infrastructures critiques. Le risque dépasse l'entreprise victime : il s'étend à l'ensemble de ses clients, créant un effet de contagion sectoriel dans l'énergie et le transport. Les organisations doivent intégrer la sécurité des tiers dans leur gouvernance des risques, renforcer les exigences contractuelles et considérer la compromission d'un intégrateur comme un scénario de crise majeur.

---

### Recommandations

* Imposer des exigences de sécurité contractuelles strictes aux intégrateurs ICS (MFA, journalisation, notification d'incident).
* Segmenter les réseaux OT/ICS et limiter les connexions entre intégrateurs et environnements clients.
* Surveiller les accès distants tiers et détecter les recherches de termes sensibles et les exfiltrations massives.
* Traiter les schémas d'architecture, électriques et réseau comme des actifs sensibles à protéger.
* Préparer un plan de réponse aux incidents OT incluant les scénarios d'attaque en aval contre les clients.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser tous les accès distants accordés aux intégrateurs ICS, consultants et prestataires tiers.
* Imposer des exigences de sécurité contractuelles aux intégrateurs (MFA, journalisation, segmentation, notification d'incident).
* Segmenter les réseaux OT/ICS et limiter les connexions entre le réseau de l'intégrateur et les environnements clients.
* Cartographier les schémas d'architecture, électriques et réseau détenus par les tiers et évaluer leur sensibilité.

#### Phase 2 — Détection et analyse

* Surveiller les accès distants des tiers et détecter les recherches de termes sensibles (« customers », « SCADA ») dans les journaux.
* Détecter la création d'archives .zip volumineuses et les transferts sortants anormaux depuis les réseaux OT.
* Analyser les connexions inhabituelles entre les environnements d'intégrateurs et les réseaux clients.
* Surveiller les tentatives d'accès aux schémas et documentations techniques des installations industrielles.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les accès tiers compromis et suspendre les sessions distantes actives.
* Isoler les segments réseau concernés et bloquer les flux sortants non nécessaires.
* Notifier les clients potentiellement exposés (utilities, transport) et partager les indicateurs disponibles.
* Préserver les preuves forensiques sur les systèmes de l'intégrateur et des clients impactés.

#### Phase 4 — Activités post-incident

* Réévaluer les contrats et les exigences de sécurité imposées aux intégrateurs tiers.
* Renforcer la segmentation IT/OT et la supervision des accès distants.
* Mettre à jour les plans de réponse aux incidents OT avec les scénarios d'attaque en aval.
* Partager les enseignements avec les CERT sectoriels et les autorités.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces de reconnaissance sur les réseaux d'intégrateurs (recherches de termes SCADA, énumération de clients).
* Chasser les archives .zip suspectes et les exfiltrations de schémas techniques.
* Rechercher des accès persistants laissés par les attaquants sur les environnements OT.
* Surveiller les connexions sortantes vers des infrastructures de commande et contrôle inconnues depuis les réseaux industriels.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1199** | Relation de confiance : exploitation de l'accès accordé à des intégrateurs ICS tiers |
| **T1083** | Découverte de fichiers et répertoires : recherche des termes « customers » et « SCADA » sur le réseau de l'intégrateur |
| **T1560** | Archivage des données collectées : environ 800 fichiers compressés en .zip en vue d'une exfiltration présumée |
| **T1005** | Collecte de données depuis le système local : informations SCADA clients, détails d'équipements ICS et schémas |

---

### Sources

* [https://www.bankinfosecurity.com/cisa-fbi-warn-ot-operators-about-third-party-hacking-a-32942](https://www.bankinfosecurity.com/cisa-fbi-warn-ot-operators-about-third-party-hacking-a-32942)
