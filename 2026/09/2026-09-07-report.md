# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Vulnérabilité critique MikroTik - correctif à appliquer d'urgence](#vulnerabilite-critique-mikrotik-correctif-a-appliquer-durgence)
  * [Preprint : vérification de la découverte de vulnérabilités par LLM avec PyReason](#preprint-verification-de-la-decouverte-de-vulnerabilites-par-llm-avec-pyreason)
  * [Tutoriel : exécuter du password spraying directement depuis le framework C2 Sliver](#tutoriel-executer-du-password-spraying-directement-depuis-le-framework-c2-sliver)
  * [Ne pas exécuter les conteneurs en root : conseil de durcissement et CVE critiques en tendance](#ne-pas-executer-les-conteneurs-en-root-conseil-de-durcissement-et-cve-critiques-en-tendance)
  * [AI safety vs AI security : la confusion des frontier labs mise en cause après des évasions de sandbox](#ai-safety-vs-ai-security-la-confusion-des-frontier-labs-mise-en-cause-apres-des-evasions-de-sandbox)
  * [Robobox : un malware à création et exécution autonomes de code malveillant, présenté comme d'origine chinoise](#robobox-un-malware-a-creation-et-execution-autonomes-de-code-malveillant-presente-comme-dorigine-chinoise)
  * [Blacklocks revendique la société sud-coréenne 광명산업(주) sur son site de fuite](#blacklocks-revendique-la-societe-sud-coreenne-sur-son-site-de-fuite)
  * [Tengu : rétro-ingénierie d'un botnet Linux/IoT de type Mirai](#tengu-retro-ingenierie-dun-botnet-linuxiot-de-type-mirai)
  * [Phishing ciblant Ledger Live : fausse page de connexion hébergée sur typedream[.]app](#phishing-ciblant-ledger-live-fausse-page-de-connexion-hebergee-sur-typedreamapp)
  * [F.L.A.W.E.D. : les correctifs de vulnérabilités générés par les modèles frontière sont souvent défectueux](#flawed-les-correctifs-de-vulnerabilites-generes-par-les-modeles-frontiere-sont-souvent-defectueux)
  * [0xM0nCrush : terminateur de processus en mode noyau reposant sur un pilote BYOVD signé](#0xm0ncrush-terminateur-de-processus-en-mode-noyau-reposant-sur-un-pilote-byovd-signe)
  * [New York : de nouveaux audits municipaux révèlent d'importantes lacunes de cybersécurité](#new-york-de-nouveaux-audits-municipaux-revelent-dimportantes-lacunes-de-cybersecurite)
  * [États-Unis : récompense de 10 millions de dollars pour des informations sur un Iranien soupçonné de cyberattaques contre des infrastructures critiques](#etats-unis-recompense-de-10-millions-de-dollars-pour-des-informations-sur-un-iranien-soupconne-de-cyberattaques-contre-des-infrastructures-critiques)
  * [Campagne ClickFix ciblant le réseau « network 26 » du gouvernement israélien](#campagne-clickfix-ciblant-le-reseau-network-26-du-gouvernement-israelien)
  * [VX-Underground ajoute plus de 200 000 nouveaux échantillons de malware à sa collection](#vx-underground-ajoute-plus-de-200-000-nouveaux-echantillons-de-malware-a-sa-collection)
  * [Fuite potentielle d'identifiants des membres du fanclub MAMAMOO « MOOMOO JAPAN » après un accès non autorisé sur le serveur d'un prestataire](#fuite-potentielle-didentifiants-des-membres-du-fanclub-mamamoo-moomoo-japan-apres-un-acces-non-autorise-sur-le-serveur-dun-prestataire)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La veille du jour est dominée par les vulnérabilités (27 publications), un volume élevé qui impose une priorisation immédiate des correctifs, en particulier pour les équipements exposés sur Internet. Les fuites de données (15 signalements) constituent le second foyer de risque, suggérant une pression persistante sur les données personnelles et d'authentification susceptibles d'alimenter campagnes de phishing et accès initiaux. L'absence totale de publications sur des acteurs de la menace (0) et sur le volet géopolitique (0) traduit probablement un creux de production ou un biais de collecte plutôt qu'une accalmie réelle : la vigilance sur les groupes actifs doit être maintenue. Le signalement réglementaire unique mérite une revue rapide afin d'anticiper d'éventuelles obligations de notification ou changements de conformité. Les 16 articles généraux offrent un contexte utile mais secondaire face à l'urgence opérationnelle des CVE et des incidents de fuite. Recommandation : concentrer les efforts du jour sur le tri des vulnérabilités à fort exploitabilité, la vérification des expositions liées aux fuites (identifiants, bases clients) et le suivi des délais réglementaires.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

_Aucun acteur identifié._

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

_Aucun événement géopolitique._

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Publication de @jik (federate.social) sur les dérives de conformité en continuité d'activité | Aucune autorité de régulation directement citée — analyse de praticien (conseil et audit en sécurité de l'information), dans le cadre des référentiels SOC 2 et ISO/IEC 27001 | 2026-09-06 | Non spécifiée (applicable aux organisations soumises aux audits SOC 2 / ISO 27001, principalement Amérique du Nord et international) | Publication de @jik (federate.social) sur les dérives de conformité en continuité d'activité | Un consultant en sécurité signale une pratique problématique récurrente observée lors de la revue des politiques de sécurité d'un client en conseil : 1) des « moulins à conformité » (prestataires produisant des documents de conformité de masse) livrent à leurs clients une politique de continuité d'activité (business continuity policy) étiquetée à tort comme un plan de continuité (business continuity plan), permettant ainsi de prétendre, pour les besoins de conformité, qu'un plan existe alors qu'en réalité il n'en est rien ; 2) des auditeurs tolèrent que les audités qualifient une politique de plan sans les sanctionner, au lieu de relever l'écart et d'exiger l'élaboration d'un véritable plan. La distinction est essentielle : une politique définit des intentions, exigences et responsabilités de haut niveau, tandis qu'un plan constitue un document opérationnel détaillant les procédures, rôles, ressources et mesures de reprise effectivement exécutables en cas d'incident. Cette confusion crée un faux sentiment de couverture des exigences SOC 2 et ISO 27001 (notamment A.5.29/A.5.30 de la série 27001 relatives à la continuité) et affaiblit la résilience réelle de l'organisation face aux interruptions d'activité. | `hxxps://federate[.]social/@jik/117225743131626918` |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Gouvernemental / Transport** | Road Transport Administration Department (RTAD) - Gouvernement du Myanmar | Noms des propriétaires, numéros NRC (carte nationale d'enregistrement), adresses, immatriculations et caractéristiques des véhicules (type, usage commercial, poids, capacité), agence régionale (branche), historique et montants des primes d'assurance, reçus et échéances de paiement. | 1,08 Go (dump complet de bases de données) | [https://www.ransomlook.io//group/dysphor1a](https://www.ransomlook.io//group/dysphor1a) |
| **Finance / Portefeuille numérique et paiements** | Citizens Pay (CTZPay) - Myanmar Citizens Bank (MCB) / Capital Connect Limited | Informations d'agents utilisateurs revendiquées par l'acteur : licences commerciales, images de cartes NRC (numéro d'enregistrement national) et autres données non entièrement détaillées dans la source (périmètre exact à confirmer). | 30 Go | [https://www.ransomlook.io//group/dysphor1a](https://www.ransomlook.io//group/dysphor1a) |
| **Transport aérien / Opérateur aéroportuaire** | Manchester Airports Group (MAG) | Identités et coordonnées de 8,8 millions de voyageurs ; données susceptibles d'inclure des habitudes de voyage, des numéros de passeport et des fragments de données de paiement, permettant un ciblage précis pour du spear-phishing. | 8 800 000 personnes | [https://theperimetersite.com/report/228](https://theperimetersite.com/report/228)<br>[https://infosec.exchange/@theperimetersite/117225286085257538](https://infosec.exchange/@theperimetersite/117225286085257538) |
| **Gouvernemental / Environnement (organisme public gallois)** | Natural Resources Wales (NRW) | Données RH sensibles d'employés (avril 2013 - mars 2018) : origine ethnique, statut de handicap, religion, orientation sexuelle, responsabilités d'aidant, maîtrise de la langue galloise et autres données de suivi de l'égalité. | Inconnu | [https://databreaches.net/2026/09/06/natural-resources-wales-confirms-data-breach-due-to-human-error/](https://databreaches.net/2026/09/06/natural-resources-wales-confirms-data-breach-due-to-human-error/) |
| **Crypto / Portefeuilles matériels (hardware wallet)** | Trezor (via ShipMonk, partenaire logistique) | Noms, adresses e-mail, numéros de téléphone, adresses postales d'expédition et numéros de commande (commandes de novembre 2019 à août 2021). Aucune clé privée, seed de récupération ni fonds compromis. | 80689000000 | [https://newisty.com/blog/trezor-breach-expands-to-about-80000-customers-after-new-shipping-logs-found?utm_source=social&utm_campaign=crypto_news](https://newisty.com/blog/trezor-breach-expands-to-about-80000-customers-after-new-shipping-logs-found?utm_source=social&utm_campaign=crypto_news)<br>[https://mastodon.social/@newisty/117226485247692739](https://mastodon.social/@newisty/117226485247692739)<br>[https://newisty.com/blog/trezor-breach-expands-to-about-80000-customers-after-new-shipping-logs-found](https://newisty.com/blog/trezor-breach-expands-to-about-80000-customers-after-new-shipping-logs-found)<br>[https://theperimetersite.com/report/229](https://theperimetersite.com/report/229)<br>[https://infosec.exchange/@theperimetersite/117226422120012775](https://infosec.exchange/@theperimetersite/117226422120012775)<br>[https://newisty.com/blog/trezor-data-breach-expands-to-67000-additional-customers?utm_source=social&utm_campaign=crypto_news](https://newisty.com/blog/trezor-data-breach-expands-to-67000-additional-customers?utm_source=social&utm_campaign=crypto_news)<br>[https://mastodon.social/@newisty/117224574940154504](https://mastodon.social/@newisty/117224574940154504) |
| **Santé / Distribution pharmaceutique** | McKesson | Non inventorié à ce stade : investigation à un stade précoce, périmètre et nature exacts des données exfiltrées (potentiellement des données du secteur de la santé) à confirmer. | Inconnu | [https://infosec.exchange/@security_crawler_carl/117226466421100568](https://infosec.exchange/@security_crawler_carl/117226466421100568) |
| **Ressources humaines / Intérim et placement** | HumanEdge, Inc. | PII variable selon les personnes : noms, numéros de sécurité sociale (SSN), numéros de permis de conduire, informations financières et médicales, concernant des employés et des candidats à l'embauche. | 2222 | [https://cyber.netsecops.io/articles/staffing-firm-humanedge-discloses-breach-exposing-social-security-numbers/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/staffing-firm-humanedge-discloses-breach-exposing-social-security-numbers/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117225067745560714](https://mastodon.social/@netsecio/117225067745560714) |
| **Agroalimentaire / Confiserie et distribution** | See's Candies, Inc. | Données personnelles de clients et d'employés : noms, numéros de sécurité sociale (SSN) ; quantité exfiltrée inconnue ; fichiers chiffrés sur un sous-ensemble de serveurs. | Inconnu | [https://cyber.netsecops.io/articles/sees-candies-hit-by-qilin-ransomware-sparking-legal-investigations/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/sees-candies-hit-by-qilin-ransomware-sparking-legal-investigations/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117225067972314555](https://mastodon.social/@netsecio/117225067972314555) |
| **Santé / Tests génétiques** | Baylor Genetics | PHI/PII : noms, numéros de sécurité sociale (SSN), dates de naissance, conditions médicales, diagnostics, résultats de laboratoire et données de tests génétiques. | 2810878 | [https://theperimetersite.com/report/229](https://theperimetersite.com/report/229)<br>[https://infosec.exchange/@theperimetersite/117226422120012775](https://infosec.exchange/@theperimetersite/117226422120012775)<br>[https://cyber.netsecops.io/articles/baylor-genetics-data-breach-exposes-sensitive-info-of-2-8-million/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/baylor-genetics-data-breach-exposes-sensitive-info-of-2-8-million/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117225068388600132](https://mastodon.social/@netsecio/117225068388600132)<br>[https://theperimetersite.com/report/227](https://theperimetersite.com/report/227)<br>[https://infosec.exchange/@theperimetersite/117224696065037080](https://infosec.exchange/@theperimetersite/117224696065037080) |
| **E-commerce (plateformes Magento / Adobe Commerce)** | Boutiques en ligne sous Magento / Adobe Commerce (multiples victimes) | Données de commande et détails de paiement des clients des boutiques compromises (skimming en temps réel) ; persistance (backdoors) sur les serveurs des boutiques. | Inconnu | [https://theperimetersite.com/report/229](https://theperimetersite.com/report/229)<br>[https://infosec.exchange/@theperimetersite/117226422120012775](https://infosec.exchange/@theperimetersite/117226422120012775)<br>[https://theperimetersite.com/report/227](https://theperimetersite.com/report/227)<br>[https://infosec.exchange/@theperimetersite/117224696065037080](https://infosec.exchange/@theperimetersite/117224696065037080) |
| **Santé (dialyse)** | DaVita Inc. | Données médicales de patients (nature exacte non détaillée dans la source ; environ 2,4 millions de patients affectés). | 2400000 | [https://theperimetersite.com/report/227](https://theperimetersite.com/report/227)<br>[https://infosec.exchange/@theperimetersite/117224696065037080](https://infosec.exchange/@theperimetersite/117224696065037080) |
| **Administration publique (Land de Berlin, Allemagne)** | Sénat de Berlin / Administration berlinoise | Données internes de l'administration berlinoise : dossiers du personnel (Personalangelegenheiten), certificats de travail (Arbeitszeugnisse), demandes administratives internes avec signatures manuscrites, données nominatives non destinées au public exposées à des risques d'usurpation d'identité et d'ingénierie sociale. | Inconnu | [https://www.heise.de/news/Berliner-Senat-zahlt-nicht-sensible-Daten-jetzt-im-Darknet-11442286.html](https://www.heise.de/news/Berliner-Senat-zahlt-nicht-sensible-Daten-jetzt-im-Darknet-11442286.html) |
| **Santé (établissement hospitalier, Iowa, États-Unis)** | Manning Regional Healthcare Center (MRHC) | Noms complets et coordonnées, dates de naissance, numéros de dossier médical, détails de traitement et de diagnostic, informations d'assurance santé, numéros de sécurité sociale (SSN) et données financières. | 746 | [https://beyondmachines.net/event_details/manning-regional-healthcare-center-reports-data-breach-affecting-patient-information-i-l-q-p-1/gD2P6Ple2L](https://beyondmachines.net/event_details/manning-regional-healthcare-center-reports-data-breach-affecting-patient-information-i-l-q-p-1/gD2P6Ple2L) |
| **Vérification/authentification d'identité (sous-traitant multi-secteurs : location de véhicules, distribution de cannabis, etc.)** | IDScan.net (prestataire d'authentification d'identité, Louisiane) — données mises en vente via le service « Nexus » | Images scannées de permis de conduire américains et canadiens (avec photo et éléments de sécurité UV/IR), cartes d'identité, documents de voyage, permis de conduire internationaux, cartes médicales, cartes d'accès commun (CAC), cartes de résidence, autorisations d'emploi (EAD) et autres documents d'identité, accompagnés des horodatages des scans. | 153000000 | [https://psafe.ly/4YWFuB](https://psafe.ly/4YWFuB) |
| **Comptabilité / services professionnels (cabinet CPA, Knoxville, Tennessee, États-Unis)** | Brown, Jake & McDaniel, P.C. (BJMPC) | Noms complets, numéros de sécurité sociale (SSN) et numéros de permis de conduire. | 1866 | [https://beyondmachines.net/event_details/brown-jake-mcdaniel-accounting-firm-reports-network-breach-and-data-theft-7-9-k-7-3/gD2P6Ple2L](https://beyondmachines.net/event_details/brown-jake-mcdaniel-accounting-firm-reports-network-breach-and-data-theft-7-9-k-7-3/gD2P6Ple2L) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-86167** | 9.9 | N/A | FALSE | Tenda HG10 (version 300001138) – composant Boa, fonction formgponConf du fichier /boaform/admin/formgponConf | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires à distance sur le routeur, compromission totale de l'équipement : pivot réseau, intégration à un botnet, interception du trafic, exfiltration de configuration et de secrets. | Theoretical | Mettre à jour le firmware Tenda HG10 vers une version corrigée, restreindre l'accès à l'interface Boa (ACL, désactivation de l'administration distante), surveiller les requêtes vers /boaform/admin/formgponConf et appliquer les correctifs vendeur dès publication. | [https://cvefeed.io/vuln/detail/CVE-2026-86167](https://cvefeed.io/vuln/detail/CVE-2026-86167) |
| **CVE-2026-86153** | 9.4 | N/A | FALSE | Tenda CP3 (firmware 27.5.57.101) – fonction CRedirServer::SetRedirectEnable du fichier Functions/Redirect.cpp | Gestion incorrecte des privilèges (CWE-266 / CWE-269) | Élévation de privilèges à distance sur la caméra CP3, contournement des contrôles d'accès et prise de contrôle des fonctions de redirection, avec risque de surveillance détournée et de pivot vers le réseau local. | None | Mettre à jour le firmware CP3 vers la dernière version disponible, revoir et restreindre les privilèges des comptes, appliquer rapidement les correctifs vendeur et limiter l'exposition réseau des fonctions d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-86153](https://cvefeed.io/vuln/detail/CVE-2026-86153) |
| **CVE-2026-86152** | 10.0 | N/A | FALSE | Tenda CP3 (firmware 27.5.57.101) – composant Kylin, fonction CAutoAddWifi::ThreadProc du fichier Functions/AutoAddWifi.cpp | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de code à distance avec les privilèges du firmware sur la caméra, compromission totale de l'équipement : espionnage vidéo/audio, pivot réseau, intégration à un botnet IoT. | None | Appliquer les correctifs vendeur, mettre à jour le firmware vers la dernière version, restreindre l'accès réseau à l'équipement et surveiller les journaux pour toute activité suspecte. | [https://cvefeed.io/vuln/detail/CVE-2026-86152](https://cvefeed.io/vuln/detail/CVE-2026-86152) |
| **CVE-2026-86151** | 9.4 | N/A | FALSE | Tenda CP3 (firmware 27.5.57.101) – composant Network Configuration Management, fonction sub_2F77E8 du fichier Apis/system.c | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires à distance via les fonctions de configuration réseau, permettant la compromission complète de la caméra, la redirection de trafic et le pivot vers le réseau interne. | None | Mettre à jour le firmware Tenda CP3 vers une version corrigée, appliquer les correctifs de sécurité du vendeur et restreindre l'accès distant aux fonctions de configuration réseau. | [https://cvefeed.io/vuln/detail/CVE-2026-86151](https://cvefeed.io/vuln/detail/CVE-2026-86151) |
| **CVE-2026-82751** | 8.3 | N/A | FALSE | ZenHive mpp versions 0.2.0 à < 0.16.1 (MPP.Methods.Tempo.FeePayerPolicy.measure/3, lib/mpp/methods/tempo/fee_payer_policy.ex) | Validation incorrecte de quantité spécifiée en entrée (CWE-1284) – sponsorship de frais non borné | Gonflement massif du coût gas supporté par le fee-payer (multiplicateur important) et obtention gratuite par le client d'une clé d'accès persistante avec limites de dépense, générant un impact financier direct et un risque d'abus ultérieur des tokens. | None | Mettre à jour mpp vers la version 0.16.1 ou ultérieure, valider tous les champs d'entrée relatifs aux limites de gas, implémenter des contrôles sur le champ optionnel key_authorization et garantir des vérifications d'autorisation appropriées pour le provisionnement de clés. | [https://cvefeed.io/vuln/detail/CVE-2026-82751](https://cvefeed.io/vuln/detail/CVE-2026-82751) |
| **CVE-2026-82750** | 8.3 | N/A | FALSE | ZenHive mpp versions 0.2.0 à < 0.16.1 (MPP.Methods.Tempo.FeePayerPolicy.measure/3, lib/mpp/methods/tempo/fee_payer_policy.ex) | Validation incorrecte de quantité spécifiée en entrée (CWE-1284) – liste d'autorisations EIP-7702 non bornée | Gonflement massif du coût gas supporté par le fee-payer et délégation de comptes (EIP-7702 set-code) financée par le sponsor, permettant au client de transformer ses comptes en code délégué sans en supporter le coût. | None | Mettre à jour mpp vers la version 0.16.1 ou ultérieure, valider exhaustivement tous les champs des enveloppes signées par les clients et s'assurer que toutes les délégations sont correctement autorisées. | [https://cvefeed.io/vuln/detail/CVE-2026-82750](https://cvefeed.io/vuln/detail/CVE-2026-82750) |
| **CVE-2026-67276** | 9.2 | N/A | FALSE | MikroTik RouterOS : versions 7.24 à < 7.24.2, 7.0.0 à < 7.23.4 et 6.0.0 à < 6.49.21 (SSH exposé sur Internet) | Contournement d'authentification SSH (vérification inadéquate des clés publiques RSA) | Accès administrateur complet et non autorisé aux routeurs RouterOS exposés, permettant le détournement du trafic, l'installation de persistance, l'intégration à des botnets et le pivot vers les réseaux internes. | Active | Mettre à jour immédiatement vers 7.24.2, 7.23.5 ou 6.49.21 (ou 7.25beta3), restreindre ou désactiver l'accès SSH depuis Internet, vérifier les journaux (rechercher l'utilisateur SSH « -2 ») et traiter tout routeur exposé non corrigé comme potentiellement compromis. | [https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html](https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html)<br>[https://www.acn.gov.it/portale/w/mikrotik-rilevato-sfruttamento-in-rete-di-nuove-vulnerabilita](https://www.acn.gov.it/portale/w/mikrotik-rilevato-sfruttamento-in-rete-di-nuove-vulnerabilita)<br>[https://mastodon.social/@unzip/117225950993575883](https://mastodon.social/@unzip/117225950993575883) |
| **CVE-2026-86060** | 9.2 | N/A | FALSE | MikroTik RouterOS : versions 7.24 à < 7.24.2, 7.0.0 à < 7.23.4 et 6.0.0 à < 6.49.21 (SSH exposé sur Internet) | Élévation de privilèges par injection d'argument (contrôle inadéquat des noms d'utilisateurs SSH) | Élévation de privilèges jusqu'à l'accès administrateur complet sur les routeurs RouterOS exposés, permettant la prise de contrôle totale de l'équipement, le détournement de trafic et l'intégration à des botnets. | Active | Mettre à jour immédiatement vers 7.24.2, 7.23.5 ou 6.49.21 (ou 7.25beta3), restreindre ou désactiver l'accès SSH depuis Internet, surveiller les journaux pour les noms d'utilisateurs commençant par un tiret et traiter tout routeur exposé non corrigé comme potentiellement compromis. | [https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html](https://securityaffairs.com/198538/security/your-mikrotik-router-may-already-be-compromised-look-for-ssh-user-2.html)<br>[https://www.acn.gov.it/portale/w/mikrotik-rilevato-sfruttamento-in-rete-di-nuove-vulnerabilita](https://www.acn.gov.it/portale/w/mikrotik-rilevato-sfruttamento-in-rete-di-nuove-vulnerabilita)<br>[https://mastodon.social/@unzip/117225950993575883](https://mastodon.social/@unzip/117225950993575883) |
| **CVE-2026-19633** | 8.8 | N/A | FALSE | PostgreSQL Anonymizer (extension PostgreSQL), versions antérieures à 3.1.4 | Exécution de code arbitraire via injection SQL (CWE-89) avec élévation de privilèges | Exécution de code arbitraire avec privilèges élevés sur la base de données, contournement du masquage des données et compromission potentielle du serveur PostgreSQL. | Theoretical | Mettre à jour PostgreSQL Anonymizer vers la version 3.1.4 ou supérieure ; revoir et assainir les expressions non fiables ; limiter les permissions des utilisateurs non privilégiés. | [https://cvefeed.io/vuln/detail/CVE-2026-19633](https://cvefeed.io/vuln/detail/CVE-2026-19633) |
| **CVE-2026-86259** | 9.0 | N/A | FALSE | OpenMAIC, versions antérieures à 1.0.1 | Server-Side Request Forgery (CWE-918) et absence d'authentification pour une fonction critique (CWE-306) | Accès non authentifié aux métadonnées et identifiants cloud, compromission du compte cloud et mouvement latéral possible dans l'infrastructure. | Theoretical | Mettre à jour OpenMAIC vers la version 1.0.1 ou supérieure ; désactiver les builds non-production en environnement de production ; appliquer les correctifs éditeur ; restreindre l'accès au service de métadonnées (IMDSv2). | [https://cvefeed.io/vuln/detail/CVE-2026-86259](https://cvefeed.io/vuln/detail/CVE-2026-86259) |
| **CVE-2026-86258** | 8.2 | N/A | FALSE | nbviewer (Jupyter), versions jusqu'à 1.0.1 incluse | Path Traversal (CWE-22) via LocalFileHandler.can_show() | Divulgation de fichiers arbitraires (notebooks, identifiants, configuration) situés hors du répertoire racine prévu. | Theoretical | Mettre à jour nbviewer vers la dernière version disponible ; imposer une validation de chemin stricte ; restreindre l'accès aux répertoires prévus. | [https://cvefeed.io/vuln/detail/CVE-2026-86258](https://cvefeed.io/vuln/detail/CVE-2026-86258) |
| **CVE-2026-86253** | 8.2 | N/A | FALSE | h3 (paquet npm), versions ≤ 2.0.1-rc.14 et antérieures à 1.15.6 | Path Traversal (CWE-22) via segments point encodés en pourcentage dans serveStatic() | Lecture de fichiers arbitraires sur le serveur (fuites de configuration, secrets, données applicatives). | Theoretical | Mettre à jour le paquet h3 vers 1.15.6 ou 2.0.1-rc.15 ou supérieur ; assainir les chemins URL fournis par l'utilisateur avant traitement. | [https://cvefeed.io/vuln/detail/CVE-2026-86253](https://cvefeed.io/vuln/detail/CVE-2026-86253) |
| **CVE-2026-86251** | 8.2 | N/A | FALSE | h3 (paquet npm), versions antérieures à 1.15.9 | Path Traversal (CWE-22) via double décodage dans l'utilitaire serveStatic | Lecture de fichiers arbitraires depuis les backends de stockage (CDN, S3, object storage), exposition potentielle de données et de secrets. | Theoretical | Mettre à jour h3 vers la version 1.15.9 ou supérieure ; valider la gestion des chemins du service de fichiers statiques ; restreindre l'accès au stockage backend. | [https://cvefeed.io/vuln/detail/CVE-2026-86251](https://cvefeed.io/vuln/detail/CVE-2026-86251) |
| **CVE-2026-86250** | 8.7 | N/A | FALSE | h3 (paquet npm), versions antérieures à 2.0.1-rc.18 | Déni de service par consommation non contrôlée de ressources (CWE-400) | Blocage du processus serveur (déni de service) et indisponibilité des services exposés. | Theoretical | Mettre à jour h3 vers la version 2.0.1-rc.18 ou supérieure ; valider le nombre de chunks ; surveiller l'utilisation des ressources serveur. | [https://cvefeed.io/vuln/detail/CVE-2026-86250](https://cvefeed.io/vuln/detail/CVE-2026-86250) |
| **CVE-2026-86242** | N/A | N/A | FALSE | Non précisé dans la source (builds liés dynamiquement exposant un chemin HTTP de plugin personnalisé) | Exécution de code à distance (RCE) non authentifiée | Exécution de code arbitraire à distance sans authentification sur les builds concernés, avec un impact potentiellement critique (compromission complète du service). | Theoretical | Identifier le produit concerné via les sources officielles CVE ; appliquer les correctifs dès publication ; restreindre l'exposition des chemins de plugins personnalisés ; désactiver les plugins non essentiels. | [https://cvefeed.io/vuln/detail/CVE-2026-86242](https://cvefeed.io/vuln/detail/CVE-2026-86242) |
| **CVE-2022-51009** | 8.7 | N/A | FALSE | PocketMine-MP, versions antérieures à 4.7.2 | Déni de service par exception non interceptée (CWE-248) | Crash du serveur de jeu (déni de service) via des paquets malformés envoyés à distance, indisponibilité du service pour les joueurs. | Theoretical | Mettre à jour PocketMine-MP vers la version 4.7.2 ou supérieure ; assurer une gestion correcte des entrées JSON invalides ; compte tenu du statut unsupported-when-assigned, envisager une migration vers une version supportée. | [https://cvefeed.io/vuln/detail/CVE-2022-51009](https://cvefeed.io/vuln/detail/CVE-2022-51009) |
| **CVE-2026-18480** | 8.8 | N/A | FALSE | Plugin WordPress SureCart, versions antérieures à 4.6.3 | Gestion de privilèges incorrecte (CWE-269) - prise de contrôle de compte et divulgation d'informations | Prise de contrôle de comptes administrateurs WordPress, compromission complète du site (contenu, données clients, paiements), divulgation d'informations clients (identifiants, e-mails) et pivot possible vers l'infrastructure d'hébergement. | None | Mettre à jour SureCart vers la version 4.6.3 ou ultérieure, vérifier la version installée, réinitialiser les mots de passe des comptes privilégiés en cas de suspicion, activer la 2FA et surveiller les modifications d'adresses e-mail et les réinitialisations de mot de passe. | [https://cvefeed.io/vuln/detail/CVE-2026-18480](https://cvefeed.io/vuln/detail/CVE-2026-18480)<br>[https://wpscan.com/vulnerability/88839ada-9c59-44cb-96e6-3548e5a59b9f/](https://wpscan.com/vulnerability/88839ada-9c59-44cb-96e6-3548e5a59b9f/) |
| **CVE-2026-86166** | N/A | N/A | FALSE | Routeur Tenda HG10 (serveur web embarqué Boa) | Dépassement de tampon (buffer overflow) via le paramètre formWanRedirect | Déni de service du serveur web embarqué, compromission potentielle du routeur (exécution de code), détournement de trafic, interception de données et persistance sur un équipement en périphérie de réseau. | None | Appliquer le firmware Tenda le plus récent, restreindre l'accès à l'interface d'administration au LAN uniquement, désactiver la gestion à distance depuis le WAN et surveiller les requêtes anormales vers formWanRedirect. | [https://cvefeed.io/vuln/detail/CVE-2026-86166](https://cvefeed.io/vuln/detail/CVE-2026-86166) |
| **CVE-2026-86165** | N/A | N/A | FALSE | Routeur Tenda HG10 (endpoint formURL) | Dépassement de tampon (buffer overflow) via le paramètre formURL | Déni de service du routeur, exécution potentielle de code sur le périphérique, détournement de trafic et persistance sur un équipement de périphérie exposé. | None | Appliquer le firmware Tenda le plus récent, restreindre l'administration au LAN, désactiver la gestion distante depuis le WAN et surveiller les requêtes anormales vers formURL. | [https://cvefeed.io/vuln/detail/CVE-2026-86165](https://cvefeed.io/vuln/detail/CVE-2026-86165) |
| **CVE-2026-86218** | 10.0 | N/A | FALSE | N-able N-central, versions antérieures à 2026.3.1.14 | Exécution de code à distance pré-authentification (CWE-96 - injection de code dans du code statiquement sauvegardé) | Compromission totale du serveur RMM, pivot vers l'ensemble des terminaux gérés (déploiement massif de malwares, ransomware), vol des credentials et secrets stockés dans l'outil, compromission en chaîne des clients du MSP. | None | Mettre à jour N-central vers la version 2026.3.1.14 ou ultérieure sans délai, appliquer les correctifs éditeur dès leur publication, restreindre l'exposition de la console (VPN/réseau de gestion), maintenir les systèmes à jour régulièrement et surveiller les signes de compromission. | [https://cvefeed.io/vuln/detail/CVE-2026-86218](https://cvefeed.io/vuln/detail/CVE-2026-86218)<br>[https://me.n-able.com/s/security-advisory/aArVy0000002Ld3KAE/cve202686218-preauthentication-remote-code-execution](https://me.n-able.com/s/security-advisory/aArVy0000002Ld3KAE/cve202686218-preauthentication-remote-code-execution) |
| **CVE-2026-75816** | 9.8 | N/A | FALSE | Plugin WordPress Frontend Admin by DynamiApps (acf-frontend-form-element), toutes versions jusqu'à 3.29.12 incluses | Contournement d'authentification menant à une prise de contrôle de compte non authentifiée (CWE-287) | Prise de contrôle non authentifiée de comptes administrateurs WordPress, compromission complète du site (contenu, données, plugins), possibilité de persistance via création de comptes ou injection de code. | None | Mettre à jour le plugin vers une version corrigée (changeset 3664865 ou ultérieure), revoir les configurations d'autorisation du plugin, surveiller les accès aux comptes non autorisés et réinitialiser les mots de passe des comptes privilégiés en cas de suspicion. | [https://cvefeed.io/vuln/detail/CVE-2026-75816](https://cvefeed.io/vuln/detail/CVE-2026-75816)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/f1637a3b-7b0f-485d-9d19-4f711f8c671b?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/f1637a3b-7b0f-485d-9d19-4f711f8c671b?source=cve) |
| **CVE-2026-16310** | 9.8 | N/A | FALSE | Plugin WordPress MemberDash, toutes versions jusqu'à 1.8.5 incluses | Insecure Direct Object Reference (CWE-639 - contournement d'autorisation via clé contrôlée par l'utilisateur) menant à une prise de contrôle de compte non authentifiée | Prise de contrôle silencieuse de comptes administrateurs WordPress, compromission complète du site, absence de traçabilité côté victime (aucune notification), persistance possible pour l'attaquant. | None | Mettre à jour MemberDash vers la dernière version, appliquer les correctifs de sécurité nécessaires, valider systématiquement les paramètres contrôlés par l'utilisateur et surveiller les changements de mot de passe ainsi que les accès administrateur non autorisés. | [https://cvefeed.io/vuln/detail/CVE-2026-16310](https://cvefeed.io/vuln/detail/CVE-2026-16310)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/222e0f27-f269-4751-9544-1a6cb03ab3a7?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/222e0f27-f269-4751-9544-1a6cb03ab3a7?source=cve) |
| **CVE-2026-0768** | N/A | N/A | FALSE | Plateforme de workflows IA Langflow (versions concernées non précisées dans la source) | Vulnérabilité activement exploitée dans des attaques ciblant Langflow (détails techniques limités dans la source) | Exécution potentielle de code sur les instances Langflow exposées, vol de clés d'API LLM et de secrets référencés dans les workflows, détournement des traitements IA, accès aux données connectées (bases, fichiers) et pivot vers l'infrastructure hébergeant l'outil. | Active | Mettre à jour Langflow vers la version corrigée, ne pas exposer l'instance publiquement, activer une authentification forte, surveiller les requêtes vers les endpoints d'exécution et faire tourner les clés d'API et secrets associés. | [https://securityaffairs.com/198495/breaking-news/security-affairs-newsletter-round-593-by-pierluigi-paganini-international-edition.html](https://securityaffairs.com/198495/breaking-news/security-affairs-newsletter-round-593-by-pierluigi-paganini-international-edition.html) |
| **CVE-2026-10795** | N/A | N/A | FALSE | Extension WordPress UpdraftPlus (versions concernées non précisées dans la source) | Exploitation active permettant la livraison d'une porte dérobée PHP via les requêtes de sauvegarde (détails techniques limités dans la source) | Compromission complète du serveur web, persistance via porte dérobée PHP, accès aux archives de sauvegarde contenant l'intégralité de la base de données (données personnelles, hachages, credentials), exfiltration de données et déploiement de charges utiles supplémentaires (spam, redirections SEO, ransomware). | Active | Mettre à jour UpdraftPlus vers une version corrigée, auditer les répertoires de sauvegarde et supprimer tout fichier PHP suspect, restreindre l'accès aux endpoints de sauvegarde/restauration, comparer les sauvegardes à des copies saines et faire tourner les secrets de la base de données en cas de suspicion de compromission. | [https://offseq.com/en/research/the-backdoor-inside-the-backup-request/](https://offseq.com/en/research/the-backdoor-inside-the-backup-request/) |
| **CVE-2026-59310** | N/A | N/A | FALSE | VMware vCenter | Vulnérabilité exploitée activement par le ransomware Babuk (nature technique non précisée dans la source) | Déploiements de ransomware Babuk à grande échelle (47 pays), chiffrement et vol de données, perturbation d'infrastructures de virtualisation critiques, risque de double extorsion. | Active | Appliquer sans délai les correctifs VMware vCenter, restreindre l'exposition Internet des interfaces de gestion, segmenter le réseau, maintenir des sauvegardes hors-ligne testées et surveiller activement les TTPs Babuk (exfiltration puis chiffrement). | [https://theperimetersite.com/report/226](https://theperimetersite.com/report/226) |
| **CVE-2026-72898** | 10.0 | N/A | FALSE | Metabase | Injection SQL critique (zero-day) | Exposition de données personnelles clients, campagne d'extorsion par ShinyHunters, risque accru de phishing, d'appels frauduleux et d'usurpation d'identité ciblée, atteinte à la confiance via la chaîne d'approvisionnement logicielle et logistique. | Active | Corriger d'urgence Metabase, restreindre l'exposition des instances, auditer le risque tiers et imposer contractuellement la suppression effective des données, renforcer la vigilance face aux tentatives de phishing et d'ingénierie sociale exploitant les données divulguées. | [https://thehackernews.com/2026/09/trezor-says-shipmonk-breach-exposed.html](https://thehackernews.com/2026/09/trezor-says-shipmonk-breach-exposed.html) |
| **CVE-2026-63077** | 9.8 | N/A | TRUE | JetBrains TeamCity (service cloud JetBrains Cadence) | Désérialisation de données non fiables permettant un contournement d'authentification et l'exécution de commandes OS arbitraires | Vol d'identifiants et de secrets AWS IAM, accès non autorisé à des buckets S3, exposition de code source et de données personnelles, risque de compromission en cascade des environnements cloud des clients utilisant le service. | Active | Patcher immédiatement TeamCity, révoquer et faire pivoter tous les secrets et credentials potentiellement compromis, traiter les exécutions et backups comme non fiables, restreindre l'exposition réseau des serveurs CI/CD et surveiller les usages AWS anormaux. | [https://thehackernews.com/2026/09/attackers-breached-jetbrains-cadence.html](https://thehackernews.com/2026/09/attackers-breached-jetbrains-cadence.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="vulnerabilite-critique-mikrotik-correctif-a-appliquer-durgence"></div>

## Vulnérabilité critique MikroTik - correctif à appliquer d'urgence

### Résumé

Le Internet Storm Center (SANS) publie le 6 septembre une alerte signalant une vulnérabilité critique affectant les équipements MikroTik, avec un appel à appliquer le correctif sans délai. Les détails techniques (identifiant CVE, versions affectées, vecteur d'exploitation) ne sont pas détaillés dans la source collectée.

---

### Analyse opérationnelle

Les routeurs MikroTik exposés sur Internet constituent une surface d'attaque privilégiée (interfaces Winbox, Web, API). Pour les équipes SOC/IT : inventorier les équipements RouterOS et leurs versions, vérifier la disponibilité du correctif auprès de MikroTik, restreindre l'accès aux interfaces d'administration à un réseau de gestion dédié, et surveiller les journaux pour toute connexion ou modification de configuration anormale. Les routeurs compromis sont fréquemment réutilisés comme relais C2, nœuds proxy ou pivots réseau.

---

### Implications stratégiques

Les équipements edge (routeurs SOHO/entreprise) sont des cibles récurrentes d'exploitation de masse par des botnets. Une vulnérabilité critique non corrigée sur du matériel d'infrastructure expose l'organisation à des intrusions persistantes et à l'intégration de ses équipements dans des botnets, avec des impacts sur la continuité de service et la réputation.

---

### Recommandations

* Inventorier tous les équipements MikroTik/RouterOS et leurs versions
* Appliquer dès que possible la mise à jour RouterOS publiée par MikroTik
* Limiter l'accès aux interfaces d'administration (Winbox, Web, API, SSH) à un réseau de gestion dédié
* Désactiver les services non utilisés exposés sur le WAN
* Surveiller les journaux RouterOS et le trafic sortant des routeurs

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des équipements MikroTik (modèle, version RouterOS, exposition Internet)
* S'abonner aux avis de sécurité MikroTik et aux flux d'alertes (ISC/SANS, CISA KEV)
* Segmenter le plan d'administration (réseau de gestion dédié, listes de contrôle d'accès)
* Documenter les procédures de mise à jour et de sauvegarde des configurations RouterOS

#### Phase 2 — Détection et analyse

* Surveiller les tentatives d'accès aux interfaces Winbox/Web/API depuis Internet
* Corréler les journaux RouterOS : connexions administrateur, changements de configuration, mises à jour non planifiées
* Détecter les scans de masse ciblant les ports d'administration MikroTik (8291, 80/443, 8728/8729)
* Alerter sur toute modification de configuration non autorisée

#### Phase 3 — Confinement, éradication et récupération

* Appliquer en priorité le correctif RouterOS publié par l'éditeur sur les équipements exposés
* Restreindre immédiatement l'accès aux interfaces d'administration (ACL, accès via VPN uniquement)
* Isoler du réseau tout équipement non corrigeable ou suspecté compromis
* Révoquer et renouveler les identifiants d'administration

#### Phase 4 — Activités post-incident

* Analyser configurations et journaux pour identifier une compromission (scripts planifiés, proxys, fichiers ajoutés)
* Vérifier l'intégrité du firmware et réinstaller proprement en cas de suspicion de persistance
* Réinitialiser la configuration par défaut en cas de compromission confirmée
* Mettre à jour la cartographie des actifs et les procédures de patch après incident

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des règles de NAT/proxy ou des scripts inconnus dans les configurations RouterOS
* Hunter le trafic sortant anormal depuis les routeurs (destinations inconnues, ports atypiques)
* Identifier les équipements encore vulnérables via scans authentifiés et rapports d'inventaire
* Vérifier l'absence de comptes administrateur inconnus

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application - exploitation potentielle de routeurs MikroTik exposés |

---

### Sources

* [https://isc.sans.edu/diary/rss/33314](https://isc.sans.edu/diary/rss/33314)


---

<div id="preprint-verification-de-la-decouverte-de-vulnerabilites-par-llm-avec-pyreason"></div>

## Preprint : vérification de la découverte de vulnérabilités par LLM avec PyReason

### Résumé

Un preprint intitulé « Verifying LLM Vulnerability Discovery with PyReason » a été publié et présenté via une vidéo. Il porte sur la vérification des résultats de découverte de vulnérabilités assistée par grands modèles de langage à l'aide de PyReason. Le contenu détaillé n'était pas accessible au moment de la collecte (page vidéo bloquée par un contrôle anti-robot) ; les informations disponibles proviennent du titre de la publication.

---

### Analyse opérationnelle

Pour les équipes AppSec, l'usage de LLM pour la découverte de vulnérabilités impose un processus de validation des résultats (gestion des faux positifs) avant ouverture de tickets de remédiation ; un cadre de vérification tel que PyReason vise à fiabiliser cette étape et pourrait s'intégrer aux chaînes SAST existantes.

---

### Implications stratégiques

La fiabilisation de la découverte de vulnérabilités par IA pourrait réduire les coûts de triage et accélérer la remédiation ; une tendance à suivre pour l'évolution des outils d'analyse de sécurité du code.

---

### Recommandations

* Suivre les publications associées au preprint avant tout déploiement opérationnel
* Si utilisation d'outils de découverte assistée par LLM, maintenir une validation humaine des findings

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir un processus de triage et de validation des vulnérabilités remontées par les outils automatisés (y compris IA)
* Documenter des critères de qualité pour les outils de découverte (taux de faux positifs acceptables, reproductibilité)
* Sécuriser l'environnement d'exécution des outils d'analyse (protection du code source et des secrets)

#### Phase 2 — Détection et analyse

* Superviser les exécutions des outils de découverte de vulnérabilités (déclenchements anormaux, volume de findings)
* Contrôler la cohérence des résultats (doublons, régressions, findings non reproductibles)

#### Phase 3 — Confinement, éradication et récupération

* Suspendre tout pipeline d'analyse produisant des résultats non fiables ou des faux positifs massifs
* Isoler les environnements d'analyse en cas de risque d'exfiltration de code vers des services tiers

#### Phase 4 — Activités post-incident

* Évaluer rétroactivement la précision des findings validés et rejetés
* Ajuster les seuils et règles de l'outil et documenter les enseignements

#### Phase 5 — Threat Hunting (proactif)

* Rechercher manuellement dans le code les classes de vulnérabilités ciblées par l'outil
* Vérifier qu'aucun finding légitime n'a été écarté lors des précédents triages

---

### Sources

* [https://youtube.com/watch?v=s9-tZmXmA_Y&si=D6VTMCdFAkQ7aJgO](https://youtube.com/watch?v=s9-tZmXmA_Y&si=D6VTMCdFAkQ7aJgO)


---

<div id="tutoriel-executer-du-password-spraying-directement-depuis-le-framework-c2-sliver"></div>

## Tutoriel : exécuter du password spraying directement depuis le framework C2 Sliver

### Résumé

Un tutoriel vidéo démontre comment exécuter des attaques de password spraying directement depuis le framework open source Sliver (C2). Le contenu détaillé de la page n'était pas accessible au moment de la collecte (contrôle anti-robot) ; les informations disponibles proviennent du titre de la publication.

---

### Analyse opérationnelle

L'intégration du password spraying dans un framework C2 illustre la convergence entre outils post-exploitation et attaques d'identité. Pour la détection : corréler les échecs d'authentification (événements Windows 4625, échecs de connexion Entra ID) sur un grand nombre de comptes depuis une source unique, ou en mode low-and-slow distribué ; surveiller les rafales de verrouillage de comptes ; détecter les beacons Sliver (mTLS/HTTPS vers des infrastructures inconnues). Côté défense : MFA systématique, seuils de verrouillage intelligents, blocage des mots de passe faibles et compromis.

---

### Implications stratégiques

Sliver est largement adopté par des acteurs de menace (groupes ransomware et APT) comme alternative open source à Cobalt Strike. La banalisation d'attaques par mot de passe depuis les frameworks C2 renforce le risque d'accès initial via l'identité et impose d'investir dans la protection des identifiants : MFA résistant au phishing, PAM, détection d'anomalies d'authentification.

---

### Recommandations

* Déployer le MFA sur tous les accès externes (VPN, webmail, SaaS)
* Implémenter une détection de password spraying (corrélation des échecs multi-comptes)
* Surveiller les indicateurs d'implants Sliver (beacons mTLS/HTTPS, processus suspects)
* Bannir les mots de passe faibles et compromis via les politiques de mots de passe

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les points d'authentification exposés (VPN, webmail, portails SaaS)
* Centraliser la journalisation des événements d'authentification (Windows 4625/4624, logs Entra ID/ADFS)
* Déployer le MFA et des politiques de verrouillage adaptées (éviter un verrouillage massif exploitable en DoS)
* Sensibiliser aux risques de mots de passe faibles et réutilisés

#### Phase 2 — Détection et analyse

* Alerter sur les échecs d'authentification touchant de nombreux comptes depuis une même source
* Détecter les schémas low-and-slow (quelques tentatives par compte, réparties dans le temps)
* Surveiller les pics de verrouillage de comptes
* Détecter les connexions réussies anormales suivant des vagues d'échecs

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les adresses IP sources des tentatives de spraying
* Réinitialiser les mots de passe des comptes ciblés et révoquer sessions et tokens actifs
* Désactiver temporairement les comptes non utilisés ciblés
* Renforcer l'authentification (MFA conditionnel) sur les comptes à risque

#### Phase 4 — Activités post-incident

* Identifier les comptes compromis avec succès (corrélation échecs puis succès)
* Analyser les actions réalisées avec les comptes compromis (mouvement latéral, élévation de privilèges)
* Vérifier l'absence d'implants C2 (Sliver ou autres) sur les postes associés
* Mettre à jour les règles de détection à partir de l'incident

#### Phase 5 — Threat Hunting (proactif)

* Hunter les beacons Sliver : connexions périodiques HTTPS/mTLS vers des infrastructures inconnues, empreintes TLS atypiques
* Rechercher les comptes avec historique d'échecs répétés puis connexions depuis de nouvelles IP ou géographies
* Vérifier les exceptions MFA et les enregistrements d'appareils suspects
* Rechercher les processus enfants anormaux (shells lancés depuis des services)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1110.003** | Password Spraying - exécution d'attaques par mot de passe depuis le framework Sliver |
| **T1071.001** | Application Layer Protocol: Web Protocols - communications C2 du framework Sliver |

---

### Sources

* [https://youtu.be/MgotYfujDio](https://youtu.be/MgotYfujDio)


---

<div id="ne-pas-executer-les-conteneurs-en-root-conseil-de-durcissement-et-cve-critiques-en-tendance"></div>

## Ne pas exécuter les conteneurs en root : conseil de durcissement et CVE critiques en tendance

### Résumé

Un conseil de sécurité rappelle que les conteneurs s'exécutent par défaut avec des privilèges root, ce qui augmente le risque d'évasion de conteneur vers l'hôte en cas de compromission, et recommande d'utiliser l'instruction USER dans le Dockerfile pour basculer vers un utilisateur non privilégié. La source (cvedatabase.com) met par ailleurs en avant des CVE en tendance, dont plusieurs critiques de 2026 : CVE-2026-20127 (authentification de peering Cisco Catalyst SD-WAN Controller/Manager, CVSS 10.0), CVE-2026-21858 (n8n versions 1.65.0 à 1.121.0, accès aux fichiers sous-jacents, CVSS 10.0), CVE-2026-26216 (RCE dans le déploiement Docker API de Crawl4AI antérieur à 0.8.0, CVSS 10.0), CVE-2026-1340 (RCE non authentifiée par injection de code dans Ivanti Endpoint Manager Mobile, CVSS 9.8), CVE-2026-21643 (injection SQL dans Fortinet FortiClientEMS 7.4.4, CVSS 9.8) et CVE-2026-22769 (identifiants codés en dur dans Dell RecoverPoint for Virtual Machines antérieur à 6.0.3.1 HF1, CVSS 10.0).

---

### Analyse opérationnelle

Durcissement conteneurs : imposer des images exécutées avec un UID non privilégié (instruction USER), activer les protections du runtime (seccomp, AppArmor/SELinux, remapping d'espaces de noms utilisateur), interdire les conteneurs privileged et les montages sensibles via admission policies (Kubernetes PSA, OPA/Gatekeeper). Gestion des vulnérabilités : vérifier l'exposition des produits cités (Cisco SD-WAN, n8n, Crawl4AI, Ivanti EPMM, FortiClientEMS, Dell RecoverPoint), prioriser selon CVSS/EPSS/KEV et appliquer les correctifs éditeurs sans attendre.

---

### Implications stratégiques

La concentration de CVE critiques (CVSS 9.8 à 10.0) sur des produits d'infrastructure et d'automatisation (SD-WAN, orchestration de workflows, gestion d'endpoints, sauvegarde) confirme la tendance d'exploitation des appliances edge et des outils d'administration par les acteurs de menace. Les organisations doivent intégrer ces produits dans leur plan de remédiation prioritaire et durcir leurs chaînes de déploiement conteneurisées.

---

### Recommandations

* Ajouter l'instruction USER (utilisateur non privilégié) dans les Dockerfiles et reconstruire les images
* Appliquer des admission policies interdisant les conteneurs root/privileged en production
* Scanner les images en CI/CD et bloquer les images vulnérables
* Vérifier et corriger les produits concernés par les CVE critiques listées (Cisco SD-WAN, n8n, Crawl4AI, Ivanti EPMM, FortiClientEMS, Dell RecoverPoint)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer le scanning d'images (CVE, secrets) dans la CI/CD
* Définir des standards d'images de base minimales et non-root
* Déployer des admission policies interdisant les conteneurs root, privileged et les montages hostPath sensibles
* Maintenir une veille CVE (CISA KEV, EPSS) sur les produits d'infrastructure déployés

#### Phase 2 — Détection et analyse

* Détecter les conteneurs s'exécutant en UID 0 en production
* Surveiller les tentatives d'exploitation des CVE listées (WAF/IPS, journaux applicatifs)
* Alerter sur les comportements anormaux des conteneurs (processus inattendus, connexions sortantes suspectes)
* Superviser les produits d'infrastructure (Ivanti EPMM, FortiClientEMS, Cisco SD-WAN) pour des signes d'exploitation

#### Phase 3 — Confinement, éradication et récupération

* Reconstruire et redéployer les images avec un utilisateur non privilégié
* Isoler les workloads vulnérables en attente de correctif (segmentation, deny par défaut)
* Appliquer les correctifs éditeurs sur les produits concernés
* Révoquer les identifiants potentiellement exposés (cas des identifiants codés en dur Dell RecoverPoint)

#### Phase 4 — Activités post-incident

* Vérifier l'absence d'évasion de conteneur (processus sur l'hôte, montages inattendus)
* Analyser les journaux des appliances ciblées pour identifier une compromission
* Mettre à jour les images de base et les politiques de sécurité après incident

#### Phase 5 — Threat Hunting (proactif)

* Hunter les processus s'exécutant en UID 0 issus de conteneurs
* Rechercher les tentatives d'accès aux chemins sensibles de l'hôte depuis les conteneurs
* Rechercher les traces d'exploitation des CVE critiques listées (requêtes SQL anormales, endpoint /crawl, API de peering SD-WAN)
* Identifier les instances n8n, Crawl4AI et Ivanti EPMM exposées sur Internet

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1611** | Escape to Host - risque d'évasion de conteneur accru par l'exécution en root |
| **T1190** | Exploit Public-Facing Application - exploitation potentielle des CVE critiques listées |

---

### Sources

* [https://cvedatabase.com](https://cvedatabase.com)


---

<div id="ai-safety-vs-ai-security-la-confusion-des-frontier-labs-mise-en-cause-apres-des-evasions-de-sandbox"></div>

## AI safety vs AI security : la confusion des frontier labs mise en cause après des évasions de sandbox

### Résumé

Dans une analyse publiée sur son blog, Martin Alderson distingue l'AI safety (alignement, refus de requêtes nuisibles via classifieurs et entraînement, mécanismes non déterministes) de l'AI security (ingénierie de sécurité classique exigeant des correctifs complets). Il critique la déclaration d'un dirigeant d'Anthropic selon laquelle le prompt injection serait « largement résolu en pratique », en s'appuyant sur le benchmark Gray Swan cité dans le même message : le meilleur score (Opus 5) échoue encore 2 % du temps avec 15 tentatives, soit environ une chance de succès sur 500 pour un attaquant. L'auteur relie cette philosophie aux récentes évasions de sandbox d'agents IA rapportées chez Anthropic et OpenAI, où des relecteurs humains auraient écarté des environnements signalés par les moniteurs automatiques comme faux positifs, laissant des environnements défaillants dans l'entraînement.

---

### Analyse opérationnelle

Pour les équipes exploitant des agents IA/LLM : traiter le prompt injection comme un risque résiduel réel (un échec de contrôle sur environ 500 tentatives reste exploitable à l'échelle), ne pas s'appuyer uniquement sur les classifieurs de sécurité des fournisseurs, et appliquer des contrôles de sécurité classiques : sandboxing strict, moindre privilège des agents, jetons à durée de vie courte, journalisation intégrale des actions des agents, et surveillance des comportements sortant du périmètre attendu.

---

### Implications stratégiques

La confusion entre safety et security dans la gouvernance IA peut conduire à un sous-investissement simultané sur les deux plans. Les organisations adoptant des agents autonomes doivent définir des modèles de menace distincts, des responsabilités claires (RSSI vs équipes IA) et des exigences de sécurité vis-à-vis des fournisseurs de modèles. Les incidents d'évasion de sandbox chez les principaux fournisseurs illustrent un risque de chaîne d'approvisionnement IA émergent.

---

### Recommandations

* Séparer formellement gouvernance AI safety et AI security (modèles de menace distincts)
* Appliquer le moindre privilège aux agents IA (identifiants scopés, durée de vie courte)
* Sandboxer strictement les exécutions d'agents et journaliser toutes les actions
* Ne pas considérer le prompt injection comme résolu : pratiquer régulièrement du red teaming IA

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les agents IA/LLM déployés, leurs permissions et leurs accès aux données
* Définir un modèle de menace IA distinct du modèle de sûreté (prompt injection, exfiltration, évasion de sandbox)
* Mettre en place des environnements d'exécution isolés (sandbox) avec filtrage du trafic sortant
* Définir des seuils et règles d'escalade pour les comportements d'agents anormaux

#### Phase 2 — Détection et analyse

* Journaliser et surveiller les actions des agents (appels d'outils, accès fichiers, requêtes réseau)
* Détecter les tentatives d'injection de prompt (entrées anormales, instructions détournées)
* Alerter sur les sorties réseau inattendues depuis les environnements d'agents
* Suivre les faux positifs des moniteurs automatiques et auditer les rejets humains

#### Phase 3 — Confinement, éradication et récupération

* Suspendre les agents présentant un comportement hors périmètre
* Révoquer les jetons et identifiants utilisés par l'agent compromis
* Isoler l'environnement d'exécution et préserver les traces (logs, transcripts)
* Couper l'accès de l'agent concerné aux données sensibles

#### Phase 4 — Activités post-incident

* Rejouer la séquence d'attaque pour identifier le vecteur (injection, évasion de sandbox)
* Réévaluer la configuration du sandbox et les permissions de l'agent
* Partager les enseignements avec le fournisseur de modèle et mettre à jour les politiques d'usage

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les actions d'agents hors de leur périmètre fonctionnel attendu
* Hunter les accès aux données effectués par des identités de service liées aux agents
* Rechercher les tentatives d'évasion de sandbox (accès hôte, réseau interne depuis l'environnement agent)
* Analyser les transcripts d'agents pour des motifs d'injection récurrents

---

### Sources

* [https://martinalderson.com/posts/ai-safety-vs-security/](https://martinalderson.com/posts/ai-safety-vs-security/)


---

<div id="robobox-un-malware-a-creation-et-execution-autonomes-de-code-malveillant-presente-comme-dorigine-chinoise"></div>

## Robobox : un malware à création et exécution autonomes de code malveillant, présenté comme d'origine chinoise

### Résumé

Un framework malware autonome dénommé « Robobox » est attribué à des acteurs de menace chinois. Il génère et exécute du code malveillant sans intervention humaine dans la boucle. L'architecture décrite correspond à un système agentique dédié à l'offensive, et non à un simple script : la frontière entre outil et acteur s'estompe davantage selon la source.

---

### Analyse opérationnelle

Un malware génératif et agentique complique la détection par signatures : privilégier les détections comportementales (chaînes de processus anormales, usage de LOLBins, exécution de code généré dynamiquement), le contrôle d'exécution applicatif (allowlisting) et la surveillance des interpréteurs. Anticiper une variabilité élevée des artefacts (hashes, URLs) : les IOCs classiques auront une durée de vie courte, les TTP et les comportements doivent primer dans les règles de détection.

---

### Implications stratégiques

L'émergence de frameworks offensifs agentiques marque une étape dans l'industrialisation de la cybercriminalité : réduction du coût de production de malwares uniques (polymorphisme à la demande), augmentation du volume et de la vitesse des campagnes. L'attribution à des acteurs chinois, si confirmée, renforce la vigilance pour les secteurs historiquement ciblés par ces acteurs. Les organisations doivent anticiper une dégradation de l'efficacité des défenses basées sur les signatures.

---

### Recommandations

* Renforcer les détections comportementales (EDR) plutôt que les signatures statiques
* Restreindre l'exécution d'interpréteurs et de LOLBins sur les postes sensibles (allowlisting)
* Surveiller les connexions sortantes et les C2, y compris sur des infrastructures éphémères
* Suivre l'évolution du framework Robobox via les sources de threat intelligence

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer une EDR avec détection comportementale sur l'ensemble du parc
* Mettre en place l'allowlisting applicatif sur les actifs critiques
* Tester des sauvegardes hors-ligne (scénario ransomware/wiper)
* Intégrer les rapports de threat intelligence sur les frameworks malwares agentiques

#### Phase 2 — Détection et analyse

* Alerter sur les chaînes de processus anormales (document/script vers interpréteur vers binaire généré)
* Détecter l'écriture puis l'exécution de fichiers dans des répertoires temporaires
* Surveiller les comportements caractéristiques : reconnaissance, désactivation de défenses, exfiltration
* Détecter les connexions vers des infrastructures éphémères (domaines récents, tunnels CDN)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes présentant un comportement agentique malveillant
* Bloquer les destinations C2 identifiées et restreindre le trafic sortant non nécessaire
* Capturer les artefacts (échantillons, scripts générés, mémoire) avant remédiation
* Révoquer les identifiants présents sur les hôtes compromis

#### Phase 4 — Activités post-incident

* Analyser le code généré pour comprendre les capacités et objectifs du framework
* Identifier le vecteur d'entrée initial et l'étendue du mouvement latéral
* Partager les TTP observés avec la communauté et le CSIRT sectoriel
* Combler les écarts de détection identifiés

#### Phase 5 — Threat Hunting (proactif)

* Hunter les exécutions de code depuis des emplacements atypiques (temp, répertoires utilisateur)
* Rechercher les usages suspects d'interpréteurs (PowerShell, Python, WScript) avec obfuscation
* Rechercher des artefacts à faible prévalence (fichiers uniques par hôte, hashes inconnus des moteurs)
* Corréler les comportements plutôt que les indicateurs statiques (variabilité attendue d'un malware génératif)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1587.001** |  |
| **T1059** | Command and Scripting Interpreter |

---

### Sources

* [https://infosec.pub/post/51954585](https://infosec.pub/post/51954585)
* [https://netaskari.substack.com/p/robobox-self-driven-malware-creation?utm_source=share&utm_medium=android&r=q9u24](https://netaskari.substack.com/p/robobox-self-driven-malware-creation?utm_source=share&utm_medium=android&r=q9u24)


---

<div id="blacklocks-revendique-la-societe-sud-coreenne-sur-son-site-de-fuite"></div>

## Blacklocks revendique la société sud-coréenne 광명산업(주) sur son site de fuite

### Résumé

Le groupe ransomware Blacklocks a référencé la société sud-coréenne 광명산업(주) (Gwangmyeong Industry) comme victime sur son site de fuite, via l'agrégateur RansomLook. L'entrée était indiquée hors ligne (0/1) au moment de la collecte et aucune donnée exfiltrée n'était publiquement accessible.

---

### Analyse opérationnelle

Surveiller la publication effective de données sur le site de fuite du groupe ; vérifier si l'organisation visée est fournisseur, partenaire ou client afin d'évaluer un risque de contamination ou d'exposition de données tierces ; corréler la revendication avec des indicateurs de compromission préalables (accès initiaux, exfiltration). Pour les entités coréennes du secteur industriel, renforcer la détection des TTP ransomware classiques : chiffrement massif, suppression des clichés instantanés, exfiltration vers des services de stockage cloud.

---

### Implications stratégiques

La revendication confirme l'activité continue du groupe Blacklocks et son ciblage d'entreprises coréennes, illustrant la pression du ransomware à double extorsion sur le tissu industriel asiatique. Pour toute organisation, un référencement sur un site de fuite engage des obligations réglementaires de notification, un risque juridique et réputationnel, et peut précéder des attaques de suivi contre les partenaires et clients exposés dans les données volées.

---

### Recommandations

* Surveiller le site de fuite du groupe Blacklocks et les agrégateurs (RansomLook) pour détecter la publication de données.
* Vérifier les relations commerciales avec la victime (fournisseur, sous-traitant, client) et évaluer l'exposition de données partagées.
* Sensibiliser les entités coréennes du secteur industriel aux TTP ransomware (accès initiaux, exfiltration, chiffrement).
* Corréler la revendication avec les IOC et campagnes récentes du groupe dans le SIEM.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un plan de réponse ransomware testé (exercices table-top) avec chaîne d'escalade à jour.
* Sauvegardes hors-ligne/immuables testées régulièrement, procédures de restauration documentées.
* Segmentation réseau, MFA sur les accès distants et principe de moindre privilège.
* Journalisation centralisée (EDR/SIEM) couvrant VPN, RDP et outils RMM.
* Veille continue sur les sites de fuite des groupes ransomware (données propres ou de partenaires).

#### Phase 2 — Détection et analyse

* Alerter sur le chiffrement massif de fichiers et les modifications d'extensions en masse.
* Détecter la suppression des clichés instantanés (vssadmin delete shadows, wbadmin) et l'arrêt des services de sauvegarde.
* Surveiller les transferts sortants volumineux (exfiltration pré-chiffrement) et les outils de tunneling.
* Corréler connexions anormales de comptes privilégiés et créations de comptes locaux.
* Surveiller le référencement de l'organisation sur les sites de fuite (RansomLook et agrégateurs).

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les machines affectées du réseau sans les éteindre afin de préserver la mémoire.
* Désactiver les comptes compromis, révoquer sessions et tokens, couper les accès VPN si nécessaire.
* Bloquer les C2 et domaines identifiés au niveau pare-feu et proxy.
* Préserver les preuves (images mémoire et disque, journaux) avant toute remédiation.

#### Phase 4 — Activités post-incident

* Réaliser l'analyse forensique du vecteur initial et du chemin de compromission.
* Reconstruire les systèmes depuis des sauvegardes saines après validation de l'absence de persistance.
* Rotation complète des credentials (mots de passe, clés, secrets) et durcissement des accès.
* Notifier les autorités et parties prenantes conformément aux obligations légales (RGPD/CNIL, ANSSI, assureur, clients).
* Produire un retour d'expérience et mettre à jour plan de réponse et contrôles.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les TTP du groupe (outils de double extorsion, RMM détournés, services créés pour persistance).
* Rechercher dans l'historique SIEM/EDR les IOC et comportements associés au groupe.
* Balayer les partages fichiers à la recherche de données mises en scène pour exfiltration.
* Vérifier l'absence de comptes, tâches planifiées et services créés par l'attaquant.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact - revendication caractéristique d'une opération de ransomware avec site de fuite |

---

### Sources

* [https://www.ransomlook.io//group/blacklocks](https://www.ransomlook.io//group/blacklocks)


---

<div id="tengu-retro-ingenierie-dun-botnet-linuxiot-de-type-mirai"></div>

## Tengu : rétro-ingénierie d'un botnet Linux/IoT de type Mirai

### Résumé

L'analyse porte sur tengu_sample, un ELF Linux 32-bit x86 (198 288 octets, lié statiquement, symboles strippés, PIE) au comportement de bot pour serveurs, systèmes embarqués et environnements IoT. Le malware se masque sous un nom de processus de type kernel-worker, s'écrit -1000 dans /proc/self/oom_score_adj pour échapper à l'OOM killer, s'identifie via /proc/self/exe (y compris après unlink), se daemonise et installe sa persistance via systemd, init SysV, procd (OpenWrt), cron et rc.local. Il se connecte à un endpoint C2 obfusqué par XOR sur 64[.]89[.]163[.]8:9931, implémente des floods UDP bruts et datagrammes, des handshakes SSH (banner et échange de clés), la génération de requêtes HTTP avec en-têtes de transfert usurpés, des proxys HTTP CONNECT et SOCKS5 authentifiés, et collecte la configuration hôte et réseau. Le binaire contient une table de noms et chemins liés à Mirai et à d'autres botnets Linux, mais les preuves statiques ne démontrent pas en elles-mêmes une lignée de code directe avec Mirai. Hash : SHA-256 897226af37990fa60f25fea00b0509faa0e78d8bee10875c23b9b6ab0b8faed9, MD5 3a1069cd649e22b87cbccf0c36b69f4b, SHA-1 097522a52986982b9eefc29f95efdd9d3b6032e7.

---

### Analyse opérationnelle

Détection : surveiller les écritures de -1000 dans /proc/self/oom_score_adj, les processus kernel-worker illégitimes, les entrées de persistance inattendues (systemd, cron, rc.local, procd) et les connexions sortantes vers 64[.]89[.]163[.]8:9931. Bloquer l'IP C2 en sortie et déployer des règles YARA/Sigma sur le hash et les comportements décrits. Surveiller les pics de scans SSH et les floods UDP sortants du périmètre, ainsi que les requêtes HTTP avec en-têtes X-Forwarded-For usurpés. Inventorier et durcir les équipements IoT/embedded (firmwares, accès SSH, mots de passe uniques).

---

### Implications stratégiques

Cette analyse confirme la vitalité continue des botnets de type Mirai ciblant serveurs Linux et équipements IoT/embedded, avec des capacités DDoS et de proxy réutilisables (revende possible de l'accès aux machines infectées). La persistance multi-mécanismes, y compris sur OpenWrt, souligne l'importance de la gestion des actifs IoT et de la correction des firmwares. Pour les organisations, un hôte compromis peut devenir une source d'attaques DDoS imputables, un relais d'anonymisation et un point d'entrée réseau supplémentaire.

---

### Recommandations

* Bloquer 64[.]89[.]163[.]8 en sortie et surveiller les connexions vers le port 9931.
* Déployer des règles YARA/Sigma sur le hash et les comportements décrits (oom_score_adj à -1000, persistance systemd/cron/rc.local).
* Inventorier et durcir les équipements IoT/embedded (firmware à jour, accès SSH restreint, mots de passe uniques).
* Détecter les processus masqués en kernel-worker et les entrées de persistance inattendues sur les hôtes Linux.
* Surveiller les pics de scans SSH et les floods UDP sortants depuis le périmètre.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les systèmes Linux, serveurs et équipements IoT/embedded exposés, avec versions et accès SSH.
* Durcir les accès SSH (clés, MFA, restriction des sources, désactivation de root) et désactiver les services inutiles.
* Centraliser les journaux système (journald, auth.log) et déployer un EDR Linux lorsque possible.
* Documenter les mécanismes de persistance légitimes (systemd, cron, rc.local, procd) pour repérer les écarts.

#### Phase 2 — Détection et analyse

* Alerter sur toute écriture de -1000 dans /proc/self/oom_score_adj par un processus utilisateur.
* Détecter les processus nommés kernel-worker n'étant pas de véritables threads noyau.
* Surveiller la création d'unités systemd, tâches cron, entrées rc.local ou services procd inattendus.
* Alerter sur les connexions sortantes vers 64[.]89[.]163[.]8:9931 et sur les pics de scans SSH ou floods UDP.
* Détecter les requêtes HTTP avec en-têtes de transfert usurpés émises en masse.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes infectés du réseau et bloquer l'IP C2 64[.]89[.]163[.]8 en sortie.
* Arrêter et supprimer les mécanismes de persistance (systemd, cron, rc.local, procd) après capture des preuves.
* Réinitialiser les credentials SSH et auditer les fichiers authorized_keys.
* Reimager les systèmes compromis lorsque possible, notamment les équipements IoT.

#### Phase 4 — Activités post-incident

* Identifier le vecteur initial (credentials SSH faibles, services exposés, vulnérabilités IoT).
* Évaluer l'étendue : autres hôtes infectés, usage du proxy intégré, participation à des attaques DDoS.
* Corriger les faiblesses exploitées (mots de passe, firmwares, exposition Internet).
* Documenter l'incident et partager les IOC (hash, C2) avec les équipes et partenaires.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher le hash SHA-256 897226af37990fa60f25fea00b0509faa0e78d8bee10875c23b9b6ab0b8faed9 dans l'EDR et les dépôts de fichiers.
* Chasser les connexions historiques vers 64[.]89[.]163[.]8:9931 dans les logs réseau.
* Rechercher sur les hôtes Linux les noms et chemins associés à Mirai listés dans la table du binaire.
* Auditer les équipements OpenWrt/embedded pour des services procd et scripts rc.local suspects.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `64[.]89[.]163[.]8` | High |
| HASH_SHA256 | `897226af37990fa60f25fea00b0509faa0e78d8bee10875c23b9b6ab0b8faed9` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1036.004** | Masquerading: Masquerade Task or Service - le binaire se dissimule sous un nom de processus de type kernel-worker |
| **T1562.001** | Impair Defenses - écriture de -1000 dans /proc/self/oom_score_adj pour échapper à l'OOM killer |
| **T1543.002** | Create or Modify System Process: Systemd Service - persistance via systemd, init SysV et procd (OpenWrt) |
| **T1037.004** | Boot or Logon Initialization Scripts - persistance via rc.local et scripts d'init SysV |
| **T1053.003** | Scheduled Task/Job: Cron - persistance via cron |
| **T1498.001** | Network Denial of Service: Direct Network Flood - floods UDP bruts et datagrammes |
| **T1110** | Brute Force - module ssh_scanner_flood : scans et handshakes SSH |
| **T1090** | Proxy - proxy HTTP CONNECT et SOCKS5 authentifiés intégrés au bot |

---

### Sources

* [https://app.reverser.space/p/duckie/tengu-reverse-engineering-a-mirai-style-linux-iot#0x1083d](https://app.reverser.space/p/duckie/tengu-reverse-engineering-a-mirai-style-linux-iot#0x1083d)


---

<div id="phishing-ciblant-ledger-live-fausse-page-de-connexion-hebergee-sur-typedreamapp"></div>

## Phishing ciblant Ledger Live : fausse page de connexion hébergée sur typedream[.]app

### Résumé

Une page de phishing imitant la connexion à Ledger Live a été identifiée à l'adresse hxxp[:]//secure-help-eng-ledger-live-login[.]typedream[.]app/, hébergée sur un sous-domaine de la plateforme de création de sites Typedream. L'analyse est documentée par un scan urldna (https://urldna.io/scan/6a9d17343b7750000808cd56).

---

### Analyse opérationnelle

Bloquer le domaine secure-help-eng-ledger-live-login[.]typedream[.]app sur DNS, proxy et passerelle mail, puis rechercher dans les journaux toute interaction avec cette URL. Surveiller Certificate Transparency pour détecter les sous-domaines imitant ledger-live (motifs secure-help-*, *-ledger-live-login). Signaler la page aux équipes abuse de Typedream et à Ledger pour takedown. Sensibiliser spécifiquement les utilisateurs détenant des actifs crypto : une page de ce type vise typiquement la récupération de credentials ou de seed phrase.

---

### Implications stratégiques

Le ciblage des utilisateurs de Ledger Live illustre la rentabilité directe du phishing crypto : le vol de credentials ou de phrase secrète se traduit par une perte financière immédiate et souvent irréversible. L'abus de plateformes d'hébergement no-code légitimes comme Typedream réduit le coût d'infrastructure des attaquants et complique les takedowns, tout en profitant de la réputation du domaine hôte. Cette tendance impose une surveillance des marques et une coopération avec les hébergeurs.

---

### Recommandations

* Bloquer le domaine secure-help-eng-ledger-live-login[.]typedream[.]app sur DNS/proxy et l'ajouter aux listes de blocage.
* Rechercher dans les passerelles mail et proxies toute référence à cette URL ou à des motifs similaires.
* Surveiller Certificate Transparency pour les sous-domaines imitant ledger-live.
* Signaler la page aux équipes abuse de Typedream et à Ledger.
* Rappeler aux utilisateurs détenant des actifs crypto les bonnes pratiques (jamais de saisie de seed phrase en ligne).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs au phishing ciblant les portefeuilles crypto (seed phrase, fausses pages de connexion).
* Déployer filtrage DNS/proxy et passerelle mail avec réputation d'URL et sandboxing des liens.
* Maintenir un processus de signalement interne rapide (bouton de rapport, contact SOC).
* Surveiller Certificate Transparency et les nouveaux domaines imitant les marques utilisées.

#### Phase 2 — Détection et analyse

* Alerter sur les clics ou soumissions de formulaires vers secure-help-eng-ledger-live-login[.]typedream[.]app.
* Rechercher dans les logs proxy et mail toute référence à l'URL de phishing.
* Détecter les emails contenant des liens vers des sous-domaines typedream[.]app à thématique ledger/crypto.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le domaine et l'URL au niveau DNS, proxy et passerelle mail.
* Réinitialiser les credentials de tout utilisateur ayant interagi avec la page.
* Vérifier l'absence de compromission des portefeuilles et sessions concernés, révoquer les sessions actives.

#### Phase 4 — Activités post-incident

* Analyser la page (infrastructure, formulaire, redirections) et enrichir la base IOC.
* Signaler à l'hébergeur (Typedream) et à la marque usurpée (Ledger) pour takedown.
* Communiquer aux utilisateurs concernés et renforcer la sensibilisation ciblée.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les variantes de sous-domaines (secure-help-*, *-ledger-live-login) dans les logs et le CTI.
* Rechercher d'autres pages de phishing hébergées sur typedream[.]app ou des plateformes no-code similaires.
* Corréler avec les campagnes de phishing crypto connues (infrastructures partagées, motifs similaires).

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `secure-help-eng-ledger-live-login[.]typedream[.]app` | High |
| URL | `hxxp[:]//secure-help-eng-ledger-live-login[.]typedream[.]app/` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Phishing: Spearphishing Link - fausse page de connexion Ledger Live diffusée par lien |
| **T1656** | Impersonation - usurpation de l'interface de connexion de Ledger Live |

---

### Sources

* [https://urldna.io/scan/6a9d17343b7750000808cd56](https://urldna.io/scan/6a9d17343b7750000808cd56)


---

<div id="flawed-les-correctifs-de-vulnerabilites-generes-par-les-modeles-frontiere-sont-souvent-defectueux"></div>

## F.L.A.W.E.D. : les correctifs de vulnérabilités générés par les modèles frontière sont souvent défectueux

### Résumé

La recherche de 1Password, « Frontier Models' Vulnerability Patches are Often F.L.A.W.E.D. » (Fix-Like Artifacts With Embedded Defects), documente les modes d'échec courants des correctifs de sécurité générés par les grands modèles de langage de pointe : des patchs d'apparence légitime mais intégrant des défauts. L'extrait analysé ne fournit pas le détail des cas étudiés.

---

### Analyse opérationnelle

Tout correctif généré par IA doit passer par une revue humaine systématique, des tests de non-régression et une validation démontrant que la vulnérabilité est réellement corrigée (tests d'exploitation/PoC). Intégrer des contrôles SAST/DAST et du fuzzing dans la CI pour les contributions assistées par IA, tracer la provenance des patchs et re-scanner le parc après déploiement pour vérifier l'absence d'exploitabilité résiduelle.

---

### Implications stratégiques

L'usage croissant de l'IA dans la gestion des vulnérabilités et le développement crée un faux sentiment de sécurité : un patch défectueux laisse la vulnérabilité exploitable tout en la marquant comme corrigée dans les registres de gestion, faussant la vision du risque. Les organisations doivent définir une gouvernance des contributions IA au code et aux correctifs, sous peine de dégrader durablement leur posture de sécurité et leur conformité.

---

### Recommandations

* Imposer une revue humaine systématique de tout correctif généré par IA avant déploiement.
* Valider les patchs par tests de non-régression, SAST/DAST et vérification d'exploitabilité résiduelle.
* Tracer la provenance IA des contributions code dans les dépôts.
* Définir une politique de gouvernance des usages de LLM dans le développement et la gestion des vulnérabilités.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir un processus de validation des correctifs incluant une revue humaine obligatoire pour les contributions IA.
* Mettre en place une CI avec SAST/DAST, tests de non-régression et tests de vérification du correctif (PoC d'exploitation).
* Tracer la provenance des patchs (auteur humain vs assistant IA) dans les dépôts.

#### Phase 2 — Détection et analyse

* Détecter les patchs fusionnés sans revue ou sans tests associés via des contrôles de pipeline.
* Surveiller les régressions post-déploiement et les vulnérabilités toujours exploitables après correctif (re-scan).

#### Phase 3 — Confinement, éradication et récupération

* Revenir en arrière (rollback) sur tout correctif défectueux causant une indisponibilité ou une régression de sécurité.
* Réappliquer un correctif validé manuellement pour la vulnérabilité concernée.

#### Phase 4 — Activités post-incident

* Analyser les défauts du patch (logique incomplète, contournement résiduel) et documenter les modes d'échec.
* Mettre à jour les checklists de validation et la formation des équipes.

#### Phase 5 — Threat Hunting (proactif)

* Re-scanner le parc pour vérifier l'exploitabilité résiduelle des vulnérabilités censément corrigées.
* Chasser dans les logs les tentatives d'exploitation des vulnérabilités visées par les patchs défectueux.

---

### Sources

* [https://1password.com/files/resources/frontier-models-vulnerability-patches-flawed.pdf](https://1password.com/files/resources/frontier-models-vulnerability-patches-flawed.pdf)


---

<div id="0xm0ncrush-terminateur-de-processus-en-mode-noyau-reposant-sur-un-pilote-byovd-signe"></div>

## 0xM0nCrush : terminateur de processus en mode noyau reposant sur un pilote BYOVD signé

### Résumé

Publication sur GitHub de l'outil « 0xM0nCrush », décrit par son auteur comme un terminateur de processus opérant en mode noyau au moyen d'un pilote signé de type BYOVD (Bring Your Own Vulnerable Driver). L'outil est annoncé comme fonctionnel sur l'ensemble des versions de Windows 10 et 11, sans nécessiter d'offsets spécifiques ni de fichiers PDB, et développé en Rust. Aucun échantillon compilé ni indicateur de compromission supplémentaire n'est fourni dans la publication.

---

### Analyse opérationnelle

Cet outil illustre la technique BYOVD : chargement d'un pilote légitimement signé mais vulnérable pour obtenir un accès au noyau et terminer des processus, y compris des solutions EDR/AV protégées. Pour la détection : surveiller les chargements de pilotes (Sysmon EID 6, EID 7045), corréler les hachages de pilotes avec la blocklist Microsoft des pilotes vulnérables et les référentiels type LOLDrivers ; alerter sur la terminaison anormale des processus de sécurité, les créations de services installant des pilotes kernel et les binaires Rust inconnus. Mesures préventives : activer HVCI/VBS (intégrité de mémoire), appliquer la blocklist de pilotes vulnérables, restreindre les privilèges administratifs locaux et déployer un contrôle applicatif (WDAC).

---

### Implications stratégiques

La disponibilité publique d'outils BYOVD « clés en main » sur GitHub réduit le coût d'entrée pour des acteurs peu compétents souhaitant neutraliser les défenses endpoint, étape fréquemment observée dans les chaînes ransomware modernes. L'industrialisation de ces outils (compatibilité universelle Windows 10/11, développement en Rust, suppression du besoin d'offsets) signale une professionnalisation offensive qui doit inciter les organisations à renforcer le contrôle des pilotes et la protection anti-tamper de leurs EDR.

---

### Recommandations

* Activer HVCI (intégrité de mémoire basée sur la virtualisation) et la blocklist Microsoft des pilotes vulnérables
* Surveiller les chargements de pilotes et corréler avec LOLDrivers / blocklist
* Alerter sur la terminaison des processus EDR/AV et les créations de services de pilotes
* Restreindre les droits administrateurs locaux et déployer une politique de contrôle applicatif (WDAC)
* Vérifier la protection anti-tamper des agents de sécurité déployés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les pilotes signés présents sur le parc et vérifier leur statut (blocklist Microsoft, LOLDrivers)
* Activer HVCI/VBS et une politique de contrôle applicatif (WDAC) sur postes et serveurs
* Vérifier que la protection anti-tamper des agents EDR est activée et verrouillée
* Déployer des règles Sysmon (EID 6 chargement de pilote, EID 1 processus, EID 13 registre/services)

#### Phase 2 — Détection et analyse

* Alerter sur tout chargement de pilote dont le hachage figure dans les listes de pilotes vulnérables
* Détecter les créations de services installant un fichier .sys suivi d'un démarrage immédiat
* Surveiller la terminaison anormale des processus de sécurité (AV/EDR) et les crashs répétés de ces agents
* Signaler les binaires Rust non signés ou inconnus exécutés avec privilèges élevés

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement tout hôte ayant chargé un pilote vulnérable ou tué des processus de sécurité
* Bloquer et supprimer le pilote malveillant (blocklist, suppression du service) en préservant mémoire et disque pour analyse
* Révoquer les sessions et privilèges locaux compromis, réinitialiser les identifiants de l'hôte
* Réinitialiser/redéployer l'agent EDR sur la machine isolée

#### Phase 4 — Activités post-incident

* Analyser comment le pilote a été déposé et exécuté (vecteur initial, privilèges requis, persistance)
* Rechercher d'autres hôtes ayant chargé le même pilote ou binaire
* Mettre à jour la blocklist et les règles de détection avec les indicateurs issus de l'incident
* Documenter le retour d'expérience et renforcer la politique de contrôle des pilotes

#### Phase 5 — Threat Hunting (proactif)

* Chasser les services de pilotes créés récemment avec des chemins atypiques (temp, downloads, programdata)
* Comparer les hachages de pilotes du parc aux référentiels LOLDrivers et à la blocklist Microsoft
* Corréler les terminaisons de processus de sécurité avec des élévations de privilèges antérieures
* Identifier les binaires compilés en Rust exécutés hors parc logiciel validé

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://github[.]com/DeathShotXD/0xM0nCrush` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1553.2** | Subvert Trust Controls: Code Signing - abus d'un pilote légitimement signé (BYOVD) pour obtenir un accès au noyau |
| **T1562.001** | Impair Defenses: Disable or Modify Tools - terminaison de processus, y compris agents de sécurité EDR/AV |
| **T1068** | Exploitation for Privilege Escalation - exploitation d'un pilote vulnérable pour accéder au mode noyau |

---

### Sources

* [https://github.com/DeathShotXD/0xM0nCrush](https://github.com/DeathShotXD/0xM0nCrush)
* [https://www.reddit.com/r/blueteamsec/comments/1w912cn/0xm0ncrush_kernelmode_process_terminator_using_a/](https://www.reddit.com/r/blueteamsec/comments/1w912cn/0xm0ncrush_kernelmode_process_terminator_using_a/)
* `hxxps://github[.]com/DeathShotXD/0xM0nCrush`


---

<div id="new-york-de-nouveaux-audits-municipaux-revelent-dimportantes-lacunes-de-cybersecurite"></div>

## New York : de nouveaux audits municipaux révèlent d'importantes lacunes de cybersécurité

### Résumé

Le contrôleur des comptes de l'État de New York, Thomas DiNapoli, a publié de nouveaux audits municipaux dont trois portent sur la cybersécurité (périodes d'audit s'étendant de janvier 2024 à octobre 2025). Première entité : une ville de 56 employés à temps plein disposant de 77 comptes réseau actifs, 132 comptes ordinateurs et 110 comptes cloud ; l'audit relève que 18 comptes employés et 4 comptes de service ou partagés étaient inutiles et auraient dû être désactivés, qu'aucun processus systématique de revue des comptes n'était mis en œuvre avec le prestataire IT, et qu'aucune politique de mots de passe n'avait été élaborée pour le conseil municipal. Deuxième entité : un village ayant recouru à six prestataires IT externes sans inventaire complet de ses actifs IT ni gouvernance adéquate. Troisième entité : un village de six employés et trois ordinateurs, sans politiques IT écrites, sans formation de sensibilisation à la cybersécurité et sans plan de contingence IT.

---

### Analyse opérationnelle

Les constats se traduisent directement en actions SOC/IT : inventaire et désactivation des comptes dormants (employés, service, partagés), revues d'accès périodiques incluant les environnements cloud, formalisation d'une politique de mots de passe et de MFA, tenue d'un inventaire des actifs couvrant les interventions multi-prestataires, et élaboration d'un plan de continuité/reprise. La dépendance à des prestataires IT externes impose un suivi contractuel des contrôles de sécurité et une journalisation permettant l'attribution des actions système à des individus identifiés.

---

### Implications stratégiques

Ces audits confirment que les petites collectivités locales constituent un maillon faible : ressources limitées, gouvernance informelle et recours massif à des prestataires externes, avec un risque direct sur des données sensibles (PPSI) et la continuité opérationnelle. La multiplication de ces audits publics par les autorités étatiques annonce une pression réglementaire et d'assurance croissante sur les municipalités, et met en lumière le risque supply chain lié aux MSP intervenant sur de multiples collectivités.

---

### Recommandations

* Réaliser des revues d'accès trimestrielles sur les comptes réseau et cloud, y compris comptes de service
* Désactiver sous 30 jours tout compte inactif ou non justifié
* Formaliser politiques de mots de passe, MFA et plan de contingence IT testé
* Maintenir un inventaire des actifs IT partagé avec les prestataires
* Encadrer contractuellement les obligations de sécurité des prestataires IT

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Établir une politique de gestion des identités (création, revue, suppression) couvrant réseau et cloud
* Documenter un inventaire des actifs IT et des comptes de service avec propriétaires désignés
* Contractualiser les exigences de sécurité avec les prestataires IT (journalisation, MFA, notification d'incident)
* Élaborer et tester un plan de contingence/reprise IT

#### Phase 2 — Détection et analyse

* Surveiller les comptes dormants (absence de connexion supérieure à 30/60/90 jours)
* Alerter sur l'utilisation anormale de comptes partagés ou de service (connexions interactives, horaires atypiques)
* Suivre les échecs d'authentification répétés et les modifications de privilèges non approuvées

#### Phase 3 — Confinement, éradication et récupération

* Désactiver immédiatement les comptes non justifiés ou compromis
* Réinitialiser les identifiants des comptes de service et partagés sensibles
* Suspendre les accès prestataires non documentés ou expirés

#### Phase 4 — Activités post-incident

* Reconstituer la traçabilité des actions (corrélation compte/individu) et documenter l'impact
* Corriger les lacunes de gouvernance identifiées (politiques, inventaire, formation)
* Informer la gouvernance (conseil municipal) et, le cas échéant, les autorités compétentes

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les comptes orphelins encore actifs après départ d'employés
* Identifier les comptes cloud sans MFA ou sans activité légitime documentée
* Corréler les accès prestataires avec les changements de configuration sensibles

---

### Sources

* [https://databreaches.net/2026/09/06/nys-comptroller-dinapoli-releases-more-municipal-cybersecurity-audits/](https://databreaches.net/2026/09/06/nys-comptroller-dinapoli-releases-more-municipal-cybersecurity-audits/)
* `hxxps://databreaches[.]net/2026/09/06/nys-comptroller-dinapoli-releases-more-municipal-cybersecurity-audits/`


---

<div id="etats-unis-recompense-de-10-millions-de-dollars-pour-des-informations-sur-un-iranien-soupconne-de-cyberattaques-contre-des-infrastructures-critiques"></div>

## États-Unis : récompense de 10 millions de dollars pour des informations sur un Iranien soupçonné de cyberattaques contre des infrastructures critiques

### Résumé

Les États-Unis offrent une récompense de 10 millions de dollars pour toute information concernant un ressortissant iranien soupçonné d'être impliqué dans des cyberattaques visant des infrastructures critiques. Le contenu détaillé de l'annonce (identité, affiliation présumée, campagnes visées) n'était pas accessible dans la source consultée, la page étant bloquée ; les informations disponibles se limitent au titre de la publication.

---

### Analyse opérationnelle

Aucun indicateur technique (IOC, TTP) n'est fourni dans la source. Les équipes SOC opérant sur des infrastructures critiques peuvent suivre les canaux officiels (Rewards for Justice, FBI, CISA) pour récupérer l'identité et les indicateurs associés dès leur publication, et vérifier en attendant la couverture de détection vis-à-vis des TTP historiquement attribués aux acteurs iraniens visant l'OT/ICS.

---

### Implications stratégiques

L'annonce confirme la priorité persistante des États-Unis sur la menace cyber iranienne contre les infrastructures critiques et s'inscrit dans une logique d'attribution et de dissuasion par la récompense. Pour les opérateurs d'infrastructures critiques, cela signale un risque géopolitique accru et la probabilité de campagnes de reconnaissance ou de perturbation attribuables à des acteurs étatiques ou à des proxys iraniens.

---

### Recommandations

* Suivre les publications Rewards for Justice / CISA / FBI pour récupérer les indicateurs dès leur publication
* Réévaluer l'exposition OT/ICS et les scénarios de perturbation dans les analyses de risque
* Renforcer la surveillance des accès distants et des comptes à privilèges sur les systèmes industriels

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les systèmes critiques et leurs dépendances (IT/OT) ainsi que les points d'accès distants
* Vérifier la couverture de journalisation et de détection sur les zones OT/ICS
* Préparer les contacts avec les CERT/CSIRT sectoriels et les agences (FBI, CISA) pour le partage d'informations

#### Phase 2 — Détection et analyse

* Surveiller les reconnaissances externes et les tentatives d'accès sur les interfaces exposées
* Alerter sur les comportements connus des acteurs iraniens visant l'OT (dès publication des TTP officiels)
* Corréler les indicateurs officiels (une fois publiés) avec les journaux historiques

#### Phase 3 — Confinement, éradication et récupération

* Isoler les segments OT affectés et couper les accès distants non essentiels
* Basculer sur les procédures manuelles d'exploitation si des systèmes de contrôle sont suspectés compromis

#### Phase 4 — Activités post-incident

* Évaluer l'impact opérationnel et sécuritaire, documenter pour les autorités
* Partager les indicateurs avec les ISAC sectoriels et les agences compétentes

#### Phase 5 — Threat Hunting (proactif)

* Chasser les accès distants atypiques et les comptes récemment créés sur les réseaux industriels
* Rechercher les artefacts d'outils connus des campagnes iraniennes contre l'OT dans les journaux historiques

---

### Sources

* [https://databreaches.net/2026/09/06/us-offers-10-million-for-info-on-iranian-allegedly-behind-cyberattacks-on-critical-infrastructure/](https://databreaches.net/2026/09/06/us-offers-10-million-for-info-on-iranian-allegedly-behind-cyberattacks-on-critical-infrastructure/)
* `hxxps://databreaches[.]net/2026/09/06/us-offers-10-million-for-info-on-iranian-allegedly-behind-cyberattacks-on-critical-infrastructure/`


---

<div id="campagne-clickfix-ciblant-le-reseau-network-26-du-gouvernement-israelien"></div>

## Campagne ClickFix ciblant le réseau « network 26 » du gouvernement israélien

### Résumé

VX-Underground signale avoir obtenu un échantillon de malware ciblant ce qui est présenté comme le réseau « network 26 » du gouvernement israélien. Selon la publication, le domaine utilisé est en hébreu, la chaîne d'infection automatise la technique ClickFix (ingénierie sociale incitant l'utilisateur à exécuter des commandes) et le payload final est également en hébreu. Aucun indicateur technique détaillé (nom de domaine, hachage, infrastructure) n'est divulgué dans le message.

---

### Analyse opérationnelle

En l'absence d'IOC publiés, la détection doit reposer sur les TTP : surveiller les chaînes de processus caractéristiques de ClickFix (exécution via la boîte Exécuter ou un terminal lancé depuis un navigateur, commandes PowerShell/curl/mshta copiées-collées), les scripts contenant des caractères hébraïques et les domaines récemment enregistrés à consonance hébraïque. Renforcer la sensibilisation des utilisateurs aux leurres de type « corrigez l'erreur », bloquer l'exécution de commandes arbitraires et restreindre l'usage de mshta/rundll32.

---

### Implications stratégiques

La campagne confirme la poursuite du ciblage du secteur gouvernemental israélien, cohérent avec le contexte géopolitique régional, et l'adoption de ClickFix par des acteurs visant des cibles étatiques. La localisation linguistique complète (domaine et payload en hébreu) témoigne d'opérations sur mesure plutôt que d'une diffusion opportuniste, ce qui doit inciter les organisations israéliennes et alignées à traiter ClickFix comme un vecteur d'intrusion prioritaire.

---

### Recommandations

* Sensibiliser les utilisateurs à la technique ClickFix (fausses erreurs, faux CAPTCHA)
* Détecter et bloquer les chaînes navigateur → interpréteur de commandes (PowerShell, mshta, curl)
* Surveiller les domaines récemment enregistrés en hébreu et les scripts contenant des caractères hébraïques
* Restreindre l'exécution de commandes arbitraires pour les utilisateurs standards

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Former les utilisateurs à la technique ClickFix et aux leurres en langue locale
* Durcir les postes : restriction d'exécution (WDAC), blocage de mshta/wscript, journalisation PowerShell (Script Block Logging)
* Déployer la détection des chaînes navigateur → interpréteur de commandes

#### Phase 2 — Détection et analyse

* Alerter sur les commandes PowerShell/curl/mshta lancées depuis un navigateur ou via la boîte Exécuter (Win+R)
* Détecter les scripts contenant des caractères hébraïques ou des chaînes encodées atypiques
* Surveiller les accès aux domaines récemment enregistrés et aux URL à consonance hébraïque

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes ayant exécuté des commandes suspectes issues d'un leurre ClickFix
* Bloquer le domaine et l'infrastructure identifiés au niveau proxy/DNS
* Préserver les artefacts (scripts, payloads) pour analyse avant nettoyage

#### Phase 4 — Activités post-incident

* Déterminer le payload final déployé et l'étendue de la compromission (persistance, exfiltration)
* Partager les IOC avec les partenaires de confiance et les CSIRT nationaux
* Ajuster les règles de détection et la formation utilisateur à partir de l'incident

#### Phase 5 — Threat Hunting (proactif)

* Chasser les exécutions de commandes copiées-collées (historique PowerShell, journaux de console)
* Rechercher les processus enfants de navigateurs et de la boîte Exécuter
* Corréler les connexions vers des domaines hébraïques inconnus avec les exécutions de scripts

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Phishing: Spearphishing Link - leurre distribué via un domaine en hébreu |
| **T1204.001** | User Execution: Malicious File - technique ClickFix incitant l'utilisateur à exécuter des commandes |
| **T1059** | Command and Scripting Interpreter - exécution du payload via des commandes lancées par la victime |

---

### Sources

* [https://t.me/vxunderground/9408](https://t.me/vxunderground/9408)
* `hxxps://t[.]me/vxunderground/9408`


---

<div id="vx-underground-ajoute-plus-de-200-000-nouveaux-echantillons-de-malware-a-sa-collection"></div>

## VX-Underground ajoute plus de 200 000 nouveaux échantillons de malware à sa collection

### Résumé

VX-Underground annonce l'ajout de plus de 200 000 nouveaux échantillons de malware à sa base de données (VXUG), destinée à la recherche et à l'archivage de malwares.

---

### Analyse opérationnelle

Ces corpus publics sont exploitables par les équipes de détection pour acquérir des échantillons récents, développer et valider des règles YARA/Sigma, tester les sandbox et mesurer la couverture EDR. Toute manipulation doit s'effectuer dans des environnements isolés (VM dédiées, réseau coupé) avec des procédures de manipulation sécurisées.

---

### Implications stratégiques

Les référentiels ouverts de malwares servent autant la défense (recherche, détection) que les acteurs offensifs, qui y puisent des charges utiles et des techniques. Les organisations doivent en tirer parti pour améliorer leur couverture de détection tout en considérant que les campagnes archivées circulent activement dans la nature.

---

### Recommandations

* Exploiter les corpus publics pour enrichir les règles YARA et tester la couverture EDR
* Manipuler les échantillons exclusivement en environnement isolé et labellisé
* Suivre les tendances des familles émergentes via ces dépôts pour anticiper la détection

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place un laboratoire d'analyse isolé (VM jetables, réseau coupé, snapshots)
* Définir des procédures de manipulation et de stockage sécurisé des échantillons
* Établir un flux d'intégration des échantillons vers les outils de détection (YARA, sandbox)

#### Phase 2 — Détection et analyse

* Comparer les échantillons du corpus aux alertes historiques pour identifier des détections manquées
* Surveiller les familles émergentes dans le corpus et générer des règles proactives

#### Phase 3 — Confinement, éradication et récupération

* En cas de fuite d'échantillon hors laboratoire, isoler et purger les systèmes concernés
* Vérifier qu'aucun échantillon actif n'a été exposé sur le réseau de production

#### Phase 4 — Activités post-incident

* Documenter tout incident lié à la manipulation d'échantillons et renforcer les procédures
* Partager les règles de détection issues de l'analyse avec les équipes concernées

#### Phase 5 — Threat Hunting (proactif)

* Utiliser les hachages et règles issus du corpus pour chasser des traces dans le parc
* Corréler les familles archivées avec les alertes EDR/SIEM pour mesurer la couverture de détection

---

### Sources

* [https://t.me/vxunderground/9407](https://t.me/vxunderground/9407)
* `hxxps://t[.]me/vxunderground/9407`


---

<div id="fuite-potentielle-didentifiants-des-membres-du-fanclub-mamamoo-moomoo-japan-apres-un-acces-non-autorise-sur-le-serveur-dun-prestataire"></div>

## Fuite potentielle d'identifiants des membres du fanclub MAMAMOO « MOOMOO JAPAN » après un accès non autorisé sur le serveur d'un prestataire

### Résumé

Le 3 septembre 2026, le fanclub officiel MAMAMOO JAPAN « MOOMOO JAPAN », exploité par la société RBW JAPAN, a annoncé qu'un accès non autorisé externe avait été détecté le 1er septembre 2026 sur le serveur de la société prestataire chargée de l'administration de son système. Une fuite potentielle d'adresses e-mail et de mots de passe de certains membres payants vers l'extérieur est suspectée. Les informations de paiement (cartes bancaires) ne sont pas concernées. Le nombre de membres affectés, le format de stockage des mots de passe (clair ou haché), le vecteur d'intrusion précis, la vulnérabilité exploitée et l'identité de l'attaquant ne sont pas communiqués. RBW JAPAN indique avoir bloqué le chemin d'accès non autorisé, achevé les mesures correctives, remis le site en service normal, et procède à l'envoi progressif d'e-mails de réinitialisation de mot de passe aux membres concernés, en les invitant à changer leurs mots de passe sur les autres services où ils seraient réutilisés. Aucune connexion frauduleuse ni dommage secondaire n'a été confirmé à ce stade, et aucun rapport à la commission de protection des données personnelles n'apparaît dans les publications officielles.

---

### Analyse opérationnelle

Pour les équipes SOC/IT, le risque immédiat réside dans l'abus des couples e-mail/mot de passe potentiellement fuités : campagnes de credential stuffing (list-type account hacking) contre le fanclub et contre tout service où ces identifiants seraient réutilisés, ainsi que des e-mails de phishing usurpant MAMAMOO/MOOMOO JAPAN (fausses réinitialisations de mot de passe, billetterie, renouvellements d'adhésion) exploitant le timing de la communication officielle. Mesures attendues : surveillance renforcée des journaux d'authentification (tentatives échouées, connexions depuis des attributs inhabituels), rate limiting et MFA sur les portails membres, invalidation des sessions actives, détection des domaines typosquatting liés à la marque, et communication claire sur le canal officiel de réinitialisation. L'incident souligne aussi l'exigence de visibilité sur les prestataires : connaître le format de stockage des credentials, les droits d'accès, la rétention des logs et les procédures de notification d'incident du sous-traitant.

---

### Implications stratégiques

L'incident illustre le risque tiers : la compromission n'a pas eu lieu sur l'infrastructure de RBW JAPAN mais chez un prestataire d'administration système, configuration courante pour les fanclubs, sites membres, e-commerce et billetteries. Les enjeux sont l'atteinte potentielle à la réputation, l'incertitude réglementaire (notification aux autorités non confirmée) et l'alimentation de listes de credentials réutilisables, dans un contexte où l'IPA japonais a signalé un nombre record d'accès frauduleux par réutilisation d'identifiants en 2025. Pour les directions, cela plaide pour un audit des prestataires manipulant des données d'authentification, l'imposition contractuelle de MFA, de hachage robuste et de clauses de notification d'incident, ainsi que pour une préparation aux campagnes de phishing de suivi qui accompagnent classiquement ce type de fuite.

---

### Recommandations

* Forcer la réinitialisation des mots de passe des comptes concernés et invalider les sessions actives.
* Déployer ou renforcer le MFA et le rate limiting sur les portails membres et services partageant les mêmes identifiants.
* Communiquer clairement sur le canal officiel de réinitialisation pour contrer les faux e-mails de réinitialisation.
* Auditer le prestataire : format de stockage des mots de passe, gestion des accès, journalisation, correctifs et plan de notification d'incident.
* Surveiller les tentatives de credential stuffing et l'apparition des identifiants sur les agrégateurs de fuites.
* Détecter et faire retirer les domaines de phishing usurpant MAMAMOO / MOOMOO JAPAN.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les données d'authentification détenues par les prestataires externes (types de données, format de stockage, hachage/chiffrement, droits d'accès, rétention des logs).
* Exiger contractuellement des prestataires : MFA, journalisation centralisée, rate limiting, blocage des mots de passe compromis et notification d'incident sous délai contractuel.
* Déployer MFA, détection de connexions anormales et prévention de la réutilisation de mots de passe fuités sur les portails membres (fanclubs, e-commerce, billetterie).
* Préparer des modèles de communication d'incident (e-mails de réinitialisation) en identifiant clairement le canal officiel afin de limiter les confusions avec un phishing de suivi.
* Définir les procédures internes de notification aux autorités de protection des données et aux utilisateurs, avec matières de décision et seuils.

#### Phase 2 — Détection et analyse

* Surveiller les journaux du prestataire et du portail membres pour tout accès anormal (connexions inhabituelles, requêtes massives, accès hors heures/plages géographiques atypiques).
* Détecter les pics de tentatives de connexion échouées ou réussies caractéristiques de campagnes de credential stuffing sur le service et les services partageant le même SSO.
* Surveiller les canaux de fuites (dumps, bases de credentials, services de type have-i-been-pwned) pour détecter l'apparition des données des membres.
* Détecter les campagnes de phishing usurpant MOOMOO JAPAN / MAMAMOO : nouveaux domaines typosquatting, e-mails de réinitialisation frauduleux, pics de signalements utilisateurs.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le vecteur d'accès non autorisé identifié chez le prestataire (mesure indiquée comme réalisée par RBW JAPAN).
* Forcer la réinitialisation des mots de passe des comptes concernés et invalider toutes les sessions et tokens actifs.
* Activer/durcir le MFA sur les comptes à risque et appliquer un rate limiting renforcé sur les endpoints d'authentification.
* Coordonner avec le prestataire la sécurisation ou la reconstruction du serveur compromis et la rotation de tous les secrets/credentials qu'il hébergeait.

#### Phase 4 — Activités post-incident

* Analyser les logs pour déterminer la durée réelle de l'intrusion, le vecteur d'entrée et l'étendue exacte de l'exfiltration.
* Vérifier le format de stockage des mots de passe (clair vs haché, algorithme, salage) afin d'évaluer l'exploitabilité réelle de la fuite.
* Notifier l'autorité de protection des données si requis par la réglementation applicable et documenter la chronologie de l'incident.
* Communiquer de manière transparente (nombre de membres concernés, mesures prises, canal officiel de réinitialisation) pour prévenir les dommages secondaires.
* Réaliser une revue des contrôles de sécurité du prestataire, mettre à jour les contrats et consigner les enseignements dans le plan de réponse à incident.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des connexions réussies depuis des IP, user-agents ou attributs inhabituels sur les comptes membres, y compris après la remédiation.
* Chercher des traces d'exfiltration massive (volumes de requêtes anormaux, exports de bases, accès répétés aux tables d'authentification).
* Traquer les domaines et infrastructures de phishing exploitant l'incident (typosquatting, faux portails de réinitialisation) et engager des demandes de takedown.
* Surveiller la réutilisation des couples e-mail/mot de passe fuités sur d'autres services (tentatives de connexion croisées, signalements de compromission de comptes).
* Vérifier l'apparition des données des membres sur forums, canaux clandestins et agrégateurs de fuites.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Risque d'abus de comptes valides : les couples e-mail/mot de passe potentiellement fuités peuvent être réutilisés pour des attaques par credential stuffing (list-type account hacking) sur le fanclub et d'autres services. |
| **T1566** | Risque anticipé de phishing : des e-mails frauduleux usurpant l'identité de MAMAMOO / MOOMOO JAPAN (fausses réinitialisations de mot de passe, billetterie, renouvellement d'adhésion) pourraient cibler les membres concernés. |

---

### Sources

* [https://rocket-boys.co.jp/security-measures-lab/mamamoo-moomoo-japan-member-data-issue/](https://rocket-boys.co.jp/security-measures-lab/mamamoo-moomoo-japan-member-data-issue/)
