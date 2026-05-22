# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [UAC-0057 - Oyster implants update targeting Ukraine](#uac-0057-oyster-implants-update-targeting-ukraine)
  * [The Gentlemen ransomware - Defense evasion and YMCA Columbia attack](#the-gentlemen-ransomware-defense-evasion-and-ymca-columbia-attack)
  * [Operation Saffron - Dismantling of First VPN infrastructure](#operation-saffron-dismantling-of-first-vpn-infrastructure)
  * [TeamPCP - Shai-Hulud supply chain campaign targeting npm](#teampcp-shai-hulud-supply-chain-campaign-targeting-npm)
  * [Kimwolf botmaster arrest - Dismantling of a major DDoS botnet](#kimwolf-botmaster-arrest-dismantling-of-a-major-ddos-botnet)
  * [GitHub repository compromise via malicious VSCode extension](#github-repository-compromise-via-malicious-vscode-extension)
  * [WantToCry ransomware - Exploitation of exposed SMB shares](#wanttocry-ransomware-exploitation-of-exposed-smb-shares)
  * [US Healthcare - External attack surface analysis and OT exposure](#us-healthcare-external-attack-surface-analysis-and-ot-exposure)
  * [Cisco Talos - BadIIS malware and SEO fraud campaigns](#cisco-talos-badiis-malware-and-seo-fraud-campaigns)
  * [Interpol cyber operation - Takedown of phishing infrastructure in Morocco](#interpol-cyber-operation-takedown-of-phishing-infrastructure-in-morocco)
  * [Identity and Access Management - Risks of active credentials for former employees](#identity-and-access-management-risks-of-active-credentials-for-former-employees)
  * [Financial Scams - Proliferation of fraudulent ads on social media](#financial-scams-proliferation-of-fraudulent-ads-on-social-media)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse des menaces cyber de mai 2026 met en lumière des mutations critiques concernant les vecteurs d'accès initiaux et la sophistication des infrastructures d'attaque. Selon les dernières conclusions du rapport DBIR de Verizon, l'exploitation automatisée des vulnérabilités a supplanté pour la première fois le vol classique d'identifiants comme principal vecteur d'intrusion. Cette accélération s'explique en grande partie par la démocratisation des outils basés sur l'intelligence artificielle (IA), permettant aux attaquants d'identifier et d'exploiter les faiblesses d'un périmètre en quelques heures seulement, réduisant drastiquement le "dwell time" disponible pour les défenseurs.

Parallèlement, la supply chain logicielle reste une cible de choix, illustrée par la campagne "Mini Shai-Hulud" orchestrée par TeamPCP sur l'écosystème npm, exploitant des vulnérabilités d'authentification OIDC ou des pipelines CI/CD pour contourner des contrôles de sécurité avancés (SLSA Build Level 3). 

Du côté de la lutte contre la cybercriminalité, on observe une intensification des opérations policières internationales coordonnées par Europol et Interpol (à l'image du démantèlement du réseau d'anonymisation "First VPN" ou du coup d'arrêt porté aux infrastructures de phishing au Maroc). Néanmoins, l'émergence des services de "lookups" (recherche de bases de données piratées) et la compromission systématique de serveurs de jeux ou de plateformes cloud rappellent la persistance du risque lié au "credential stuffing" et à la réutilisation d'identifiants au sein des parcs d'entreprises.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **UAC-0057** | Gouvernement, Défense, Secteur Public (Ukraine) | Campagnes d'hameçonnage ciblé utilisant des implants personnalisés pour l'exfiltration et le contrôle persistant du registre Windows. | T1059 (Command and Scripting Interpreter)<br>T1105 (Ingress Tool Transfer) | [CERT-UA](https://cert.gov.ua/article/6315762) |
| **The Gentlemen** | Multi-sector, Construction, Éducation, Santé | Ransomware-as-a-Service (RaaS) exploitant les failles de périmètre, avec contournement persistant de Microsoft Defender via scripts PowerShell et exfiltration préalable. | T1053.005 (Scheduled Task)<br>T1059.001 (PowerShell)<br>T1078 (Valid Accounts) | [Huntress](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps) |
| **TeamPCP** | Développement Logiciel, Technologie, Cloud | Compromission de chaîne d'approvisionnement npm/PyPI via le ver Shai-Hulud, empoisonnement de pipelines GitHub Actions et vol de jetons d'identité OIDC. | T1195.001 (Active supply chain compromise)<br>T1195.002 (Compromise Software Dependencies) | [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| **CyberAv3ngers** | Santé, Énergie, Eau, Industrie manufacturière | Attaques disruptives d'infrastructures critiques via l'exploitation d'équipements OT connectés (PLCs Rockwell Automation). | T1190 (Exploit Public-Facing Application)<br>T0815 (Asset Identification) | [Flare](https://flare.io/learn/resources/blog/us-healthcare-sector-wide-external-attack-surface-analysis) |
| **Dort (Jacob Butler)** | Infrastructures Critiques, Secteur Public, FAI | Enrôlement massif d'équipements IoT (caméras, cadres photo) pour opérer le botnet Kimwolf et mener des attaques DDoS à haut volume (jusqu'à 30 Tbps). | T1584.005 (Botnet)<br>T1498 (Network Denial of Service) | [KrebsOnSecurity](https://krebsonsecurity.com/2026/05/alleged-kimwolf-botmaster-dort-arrested-charged-in-u-s-and-canada/) |
| **HexDex** | Secteur Public, Automobile, Assurances (France) | Intrusion opportuniste, scraping agressif d'API et extraction de bases de données massives d'entités administratives et privées françaises pour revente et notoriété. | T1114 (Email Collection)<br>T1567 (Exfiltration Over Web Service) | [Le Monde](https://www.lemonde.fr/pixels/article/2026/05/21/j-etais-seul-dans-ma-chambre-et-j-ai-derape-la-derive-du-hackeur-hexdex-jeune-maraicher-vendeen-en-quete-de-reconnaissance_6691824_4408996.html) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Arctique, Europe, Danemark, Groenland** | Défense | Souveraineté militaire et dissuasion industrielle | La guerre prolongée en Ukraine pousse l'Union Européenne et ses alliés nordiques à réinvestir dans la résilience physique et logique des liaisons maritimes, des capteurs polaires et des infrastructures militaires de l'Arctique. | [IRIS France](https://www.iris-france.org/europes-arctic-test-from-ambition-to-capability/) |
| **France, Russie, Niger, Chine** | Énergie Nucléaire | Espionnage industriel lié aux pipelines d'IA | L'introduction croissante de l'IA au sein du cycle de vie du combustible nucléaire (extraction d'uranium, jumeaux numériques d'enrichissement) expose les infrastructures régaliennes françaises à des cyber-espionnages et exfiltrations de modèles stratégiques. | [Portail de l'IE](https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/ia-cycle-du-combustible-extraction-enrichissement/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Sécurité logicielle et conformité CRA | Open Source Security Foundation (OpenSSF) | 2026-05-21 | International | OpenSSF-CRA-2026-05-21 | Expansion communautaire et lancement d'initiatives pour harmoniser le développement open-source face aux exigences du Cyber Resilience Act (CRA) européen. | [OpenSSF Press](https://openssf.org/press-release/2026/05/21/openssf-notes-quarter-of-growth-with-new-members-added-ai-security-resources-and-growing-community/) |
| Campagne pour les droits numériques ("Fight for Us") | EDRi (European Digital Rights) | 2026-05-21 | Union Européenne | EDRi-FightForUs-2026 | Mobilisation de la société civile contre les propositions de dérégulation numérique sous prétexte de simplification administrative ("Digital Fitness Check"). | [EDRi](https://edri.org/our-work/fight-for-us-not-for-them-a-public-interest-vision-for-eu-tech-policy-new-speakers-announced/) |
| Réforme de la loi contre la cybercriminalité | Experts informatiques et Gouvernement du Royaume-Uni | 2026-05-21 | Royaume-Uni | UK-CMA-2026 | Critiques sévères contre les propositions de réformes du Computer Misuse Act, jugées inadaptées face aux menaces actuelles et préjudiciables aux chercheurs en sécurité. | [DataBreaches.net](https://databreaches.net/2026/05/21/uk-plans-for-cybercrime-law-reform-would-protect-almost-no-one-experts-warn/?pk_campaign=feed&pk_kwd=uk-plans-for-cybercrime-law-reform-would-protect-almost-no-one-experts-warn) |
| Connectivité énergétique et Services Financiers EEE | Comité Économique et Social Européen / Commission Mixte | 2026-05-22 | Europe | OJ:C_202602540 / CELEX:22026D0956 | Harmonisation des normes de cybersécurité des réseaux de distribution électrique et révision de la conformité des services financiers dans l'espace économique. | [OJ:C_202602540](https://eur-lex.europa.eu/legal-content/AUTO/?uri=OJ:C_202602540)<br>[CELEX:22026D0956](https://eur-lex.europa.eu/legal-content/AUTO/?uri=CELEX:22026D0956) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Santé / Secteur Hospitalier** | NYC Health + Hospitals, Université de la Sarre | Informations de santé protégées (PHI), diagnostics, sécurité sociale, données biométriques complexes (empreintes digitales et palmaires). | 1,8 million d'enregistrements (NYC), dizaines de milliers (Allemagne) | [Flare](https://flare.io/learn/resources/blog/us-healthcare-sector-wide-external-attack-surface-analysis)<br>[Mastodon ReginaMuehlich](https://mastodon.social/@ReginaMuehlich/116614256181244000)<br>[Mastodon Drahardja](https://sfba.social/@drahardja/116614086761770205) |
| **Éducation** | Plateforme Canvas LMS (Territoires du Nord-Ouest, Canada) | Adresses e-mail, identités d'étudiants et d'enseignants, configurations de cours. | ~1 700 personnes | [Mastodon Mirror](https://mastodon.hongkongers.net/@cbcnorth_mirror/116615295424557433)<br>[Mastodon Agent0x0](https://infosec.exchange/@agent0x0/116614526716889945) |
| **Secteur Public / Assurances** | ANTS, France Travail, Free, Autovision, Citoyens Français | Identités complètes, mots de passe en clair, revenus fiscaux, numéros d'immatriculation. | 12 millions de dossiers (ANTS), agrégation de plusieurs dizaines de millions de données (Lookups) | [Le Monde Lookups](https://www.lemonde.fr/pixels/article/2026/05/21/les-donnees-volees-et-leurs-moteurs-de-recherche-armes-redoutables-des-cybercriminels_6691908_4408996.html)<br>[Le Monde HexDex](https://www.lemonde.fr/pixels/article/2026/05/21/j-etais-seul-dans-ma-chambre-et-j-ai-derape-la-derive-du-hackeur-hexdex-jeune-maraicher-vendeen-en-quete-de-reconnaissance_6691824_4408996.html)<br>[Le Monde Podcast](https://www.lemonde.fr/podcasts/article/2026/05/21/arnaques-telephoniques-radioscopie-d-un-fleau-social_6691805_5463015.html) |
| **Jeux en ligne / Divertissement** | Dragonica Lunaris, site parodique Windows93 | Adresses e-mail, hachages de mots de passe (bcrypt), adresses IP, mots de passe en texte brut. | 172 398 comptes | [HaveIBeenPwned Dragonica](https://haveibeenpwned.com/Breach/Dragonica)<br>[HaveIBeenPwned Windows93](https://haveibeenpwned.com/Breach/Windows93) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-20223 | TRUE  | Active    | 6.5 | 10.0  | (1,1,6.5,10.0) |
| 2 | CVE-2024-12802 | TRUE  | Active    | 6.5 | 9.4   | (1,1,6.5,9.4)  |
| 3 | CVE-2026-33000 | FALSE | Théorique | 2.0 | 9.1   | (0,0,2.0,9.1)  |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-20223** | 10.0 | N/A | **TRUE** | **6.5** | Cisco Secure Workload | Insuffisance d'authentification API | SSRF / Auth Bypass | Active | Appliquer la mise à jour (versions 3.10.8.3 ou 4.0.3.17) et isoler l'accès aux API REST internes. | [Security Affairs](https://securityaffairs.com/192473/security/cisco-fixed-maximum-severity-flaw-cve-2026-20223-in-secure-workload.html)<br>[CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0628/) |
| **CVE-2024-12802** | 9.4 | N/A | **TRUE** | **6.5** | SonicWall Gen6 SSL-VPN | Traitement défectueux d'attributs LDAP (formats UPN/SAM) | Auth Bypass (MFA Bypass) | Active | Effectuer la reconfiguration LDAP manuelle en six étapes ou migrer vers la génération Gen7/Gen8. | [Security Affairs](https://securityaffairs.com/192477/hacking/attackers-are-bypassing-mfa-on-sonicwall-vpns-because-something-was-wrong-with-previous-fix.html) |
| **CVE-2026-33000** | 9.1 | N/A | **FALSE** | **2.0** | Ubiquiti UniFi OS Server | Validation d'entrée incorrecte (CWE-20) | RCE (Command Injection) | Théorique | Aucun correctif publié. Restreindre l'accès réseau à l'interface d'administration UniFi OS au segment d'administration local. | [OffSeq Threat Radar](https://infosec.exchange/@offseq/116615638632098258) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Оновлений інструментарій UAC-0057 | UAC-0057 - Oyster implants update targeting Ukraine | Sujet d'espionnage étatique actif ciblant des infrastructures militaires et étatiques clés. | [CERT-UA](https://cert.gov.ua/article/6315762) |
| The Gentleman Ransomware | The Gentlemen ransomware - Defense evasion and YMCA Columbia attack | Attaque active de ransomware-as-a-service avec techniques de contournement Defender documentées. | [Huntress](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps) |
| Global law enforcement operation takes First VPN offline | Operation Saffron - Dismantling of First VPN infrastructure | Démantèlement d'infrastructure d'anonymisation majeure utilisée par les opérateurs de rançongiciels. | [Security Affairs](https://securityaffairs.com/192491/cyber-crime/global-law-enforcement-operation-takes-first-vpn-offline.html) |
| The npm Threat Landscape (TeamPCP) | TeamPCP - Shai-Hulud supply chain campaign targeting npm | Attaque sophistiquée ciblant la chaîne d'approvisionnement des développeurs. | [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| Alleged Kimwolf Botmaster ‘Dort’ Arrested | Kimwolf botmaster arrest - Dismantling of a major DDoS botnet | Fin de cavale pour l'opérateur d'un botnet IoT responsable d'attaques à grand volume. | [KrebsOnSecurity](https://krebsonsecurity.com/2026/05/alleged-kimwolf-botmaster-dort-arrested-charged-in-u-s-and-canada/) |
| GitHub confirms breach of 3,800 repos via malicious extension | GitHub repository compromise via malicious VSCode extension | Compromission massive de dépôts via un vecteur d'attaque d'extension IDE. | [DataBreaches.net](https://databreaches.net/2026/05/21/github-confirms-breach-of-3800-repos-via-malicious-vscode-extension/) |
| WantToCry Ransomware Campaign | WantToCry ransomware - Exploitation of exposed SMB shares | Nouvelle campagne exploitant les protocoles d'administration sans binaire local ("fileless"). | [AlienVault OTX](https://social.raytec.co/@techbot/116615530759805235) |
| What Attackers See When They Look at US Healthcare | US Healthcare - External attack surface analysis and OT exposure | Analyse sectorielle critique des vulnérabilités de périmètre d'hôpitaux. | [Flare](https://flare.io/learn/resources/blog/us-healthcare-sector-wide-external-attack-surface-analysis) |
| The art of being ungovernable (BadIIS) | Cisco Talos - BadIIS malware and SEO fraud campaigns | Analyse d'un composant de persistance Web (IIS Module) utilisé pour la fraude SEO. | [Cisco Talos](https://blog.talosintelligence.com/the-art-of-being-ungovernable/) |
| INTERPOL Cyber Operation Involving Morocco | Interpol cyber operation - Takedown of phishing infrastructure in Morocco | Opération policière de neutralisation de botnets et d'infrastructures de phishing. | [DataBreaches.net](https://databreaches.net/2026/05/21/kaspersky-group-ib-detail-role-in-interpol-cyber-operation-involving-morocco/) |
| Today’s reminder to terminate employees’ credentials | Identity and Access Management - Risks of active credentials for former employees | Analyse pratique des failles opérationnelles de gestion de cycle de vie des identités. | [DataBreaches.net](https://databreaches.net/2026/05/21/todays-reminder-to-terminate-employees-credentials-when-their-employment-ends/) |
| Arnaques financières en ligne | Financial Scams - Proliferation of fraudulent ads on social media | Analyse du vecteur de distribution de malwares et de vols financiers via publicité malveillante. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/05/21/arnaques-financieres-en-ligne-des-associations-de-consommateurs-exigent-des-actions_6691867_4408996.html) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| ISC Stormcast (May 21st / May 22nd) | Podcast d'actualité cyber généraliste (non focalisé sur un cas d'incident unique ou une nouvelle menace détaillée). | [SANS ISC](https://isc.sans.edu/diary/rss/33004) |
| Selective HTTP Proxying in Linux | Tutoriel technique d'administration système (pas d'actualité de menace directe). | [SANS ISC](https://isc.sans.edu/diary/rss/33002) |
| Continuous Security Validation | Guide méthodologique de bonnes pratiques (hors cadre menace active). | [GuidePoint Security](https://www.guidepointsecurity.com/blog/continuous-security-validation-best-practices-a-practical-guide-for-security-teams/) |
| How Huntress Uses Managed SIEM | Contenu orienté promotionnel/explication produit. | [Huntress](https://www.huntress.com/blog/how-huntress-uses-managed-siem-to-detect-threats-faster) |
| Proofpoint Integrates with Claude API | Annonce produit commerciale. | [Proofpoint](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-integrates-claude-compliance-api-extend-data-security-and) |
| The Vulnerability Flood Board Conversation | Billet d'opinion méthodologique pour RSSI. | [Recorded Future](https://www.recordedfuture.com/blog/vulnerability-board-conversation) |
| Apple Blocks 2 Million Apps | Rapport d'activité d'entreprise annuel global sans incident technique spécifique. | [Security Affairs](https://securityaffairs.com/192484/security/apple-blocks-over-2-million-apps-in-2025-fraud-crackdown.html) |
| Discord E2EE call default | Annonce d'implémentation fonctionnelle légitime de chiffrement. | [Security Affairs](https://securityaffairs.com/192463/security/discord-adds-end-to-end-encryption-to-voice-and-video-calls-by-default.html) |
| Securing NVIDIA AI stacks | Guide d'implémentation technique d'outils de protection. | [Sysdig](https://webflow.sysdig.com/blog/securing-nvidia-ai-stacks-for-enterprise-environments) |
| Streamline vulnerability remediation headless | Contenu promotionnel de produit de remédiation automatisée par IA. | [Sysdig](https://webflow.sysdig.com/blog/streamline-vulnerability-remediation-with-headless-cloud-security) |
| PH4NTXM custom firmware | Projet open-source personnel de micrologiciel alternatif. | [Infosec Exchange](https://infosec.exchange/@PH4NTXMOFFICIAL/116615672306148266) |
| Local patching open-source software | Billet d'opinion d'un ingénieur sécurité. | [Mastodon](https://mstdn.social/@msw/116615609141495941) |
| CTF game ruined by LLMs | Réflexion philosophique sur la pédagogie et l'IA. | [Infosec Exchange](https://infosec.exchange/@AmmarSpaces/116615501847283152) |
| Getting hacked isn't the problem | Billet d'opinion sur la communication de crise. | [Infosec Exchange](https://infosec.exchange/@agent0x0/116614526716889945) |
| CVE-2026-8485 (MOVEit Automation) | Score composite insuffisant (< 1.0) dans la grille de criticité. | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0624/) |
| CVE-2026-9082 (Drupal) | Classée dans Liste_Vulnérabilités (vulnérabilités de périmètre exclues de la section Articles). | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0629/) |
| Apereo CAS / Splunk / BIND (CERT-FR) | Classés dans Liste_Vulnérabilités (vulnérabilités de périmètre exclues de la section Articles). | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0625/) |
| Fastjson 1.2.68 Autotype | Classée dans Liste_Vulnérabilités (vulnérabilités de périmètre exclues de la section Articles). | [Mastodon](https://mastodon.social/@liliumf/116615338498461675) |
| Windows 10 PagedPool exploit | Classée dans Liste_Vulnérabilités (vulnérabilités de périmètre exclues de la section Articles). | [Mastodon](https://mastodon.social/@liliumf/116615255981812407) |
| ZDI-26-318 / ZDI-26-319 (Kemp) | Classées dans Liste_Vulnérabilités (vulnérabilités de périmètre exclues de la section Articles). | [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-26-318/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="uac-0057-oyster-implants-update-targeting-ukraine"></div>

## UAC-0057 - Oyster implants update targeting Ukraine

### Résumé technique

Le CERT-UA a documenté une mise à jour d'envergure de la suite d'implants malveillants exploités par le groupe d'espionnage russe UAC-0057 (également connu sous le nom d'APT28 ou Sofacy). La campagne utilise un vecteur initial classique d'hameçonnage ciblé (phishing) contenant des pièces jointes malveillantes ou des liens redirigeant vers des archives compressées.

L'analyse technique révèle l'exécution d'une chaîne d'infection structurée en plusieurs étapes de charge utile (payloads) :
1. **Oysterfresh** : Un chargeur (loader) léger initialement exécuté en mémoire pour contourner la détection heuristique et inspecter l'environnement de l'hôte.
2. **Oystershuck** : L'implant de base, chargé d'établir la persistance au sein de la machine via des modifications ciblées du registre Windows et de configurer les canaux de communication cryptés avec l'infrastructure de commande et de contrôle (C2).
3. **Oysterblues** : Le module d'exfiltration finale et d'exécution interactive de commandes, conçu pour rechercher et dérober des documents spécifiques sur les machines compromises.

La persistance est assurée par l'enregistrement de binaires usurpant l'identité d'applications légitimes, notamment via le fichier `EdgeApp.exe`. Le groupe cible prioritairement des entités gouvernementales et militaires ukrainiennes afin de collecter du renseignement tactique.

---

### Analyse de l'impact

L'impact opérationnel pour les entités touchées réside dans la compromission totale de la confidentialité des données hébergées sur les parcs gouvernementaux. La sophistication technique de la menace est élevée, caractérisée par une évasion active des EDR (par obfusquation de code et injection dans des processus de confiance de type Edge) et l'utilisation d'une infrastructure C2 résiliente.

---

### Recommandations

* Bloquer l'exécution de scripts d'administration non signés à l'aide d'AppLocker ou de Windows Defender Application Control (WDAC).
* Configurer la surveillance stricte des clés de registre associées au démarrage automatique (Run/RunOnce).
* Restreindre les flux réseau sortants des postes administratifs vers des destinations non standards.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre à jour les règles de détection EDR et de proxy réseau pour identifier l'usage de l'exécutable masqué `EdgeApp.exe`.
* S'assurer que les journaux de modifications de registre Windows (Event ID 4657) sont activés et centralisés vers le SIEM.

#### Phase 2 — Détection et analyse
* Rechercher les instances d'exécution de `EdgeApp.exe` en dehors des chemins d'installation standards de Microsoft.
* **Requête EDR (syntaxe générique) :**
  `process_name == "EdgeApp.exe" AND parent_process != "explorer.exe"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler logiquement le poste via la quarantaine EDR pour stopper toute exfiltration.
* **Éradication :** Supprimer l'artefact malveillant localisé à l'emplacement identifié et purger les clés de registre de persistance malveillantes.
* **Récupération :** Restaurer la configuration système d'origine et imposer un changement de mot de passe global pour les comptes de l'utilisateur affecté.

#### Phase 4 — Activités post-incident
* Analyser l'archive malveillante d'origine pour en extraire d'éventuels nouveaux sous-domaines de C2 non répertoriés.
* Notifier les autorités gouvernementales compétentes (CERT national) de la nature de l'intrusion.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exécutions d'outils de transfert de fichiers non autorisés | T1105 | Logs EDR (Process creation) | `process.command_line: "*EdgeApp.exe*" OR file.path: "*EdgeApp.exe*"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Hash SHA256 | `07ff534b425b09123577067d4aebcdecd523acbec8d1b180179aca1377c0a4e7` | Charge utile de l'implant Oystershuck | Haute |
| Nom de fichier | `EdgeApp.exe` | Binaire de persistance usurpant une application légitime | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1059** | Execution | Command and Scripting Interpreter | Exécution de commandes shell pour orchestrer l'infection de l'hôte. |
| **T1105** | Command and Control | Ingress Tool Transfer | Téléchargement des étapes de charges utiles additionnelles (implants). |

---

### Sources

* [CERT-UA Advisory](https://cert.gov.ua/article/6315762)

---

<div id="the-gentlemen-ransomware-defense-evasion-and-ymca-columbia-attack"></div>

## The Gentlemen ransomware - Defense evasion and YMCA Columbia attack

### Résumé technique

Les équipes de Huntress ont documenté l'activité et le mode opératoire du groupe criminel opérant le rançongiciel "The Gentlemen" (Ransomware-as-a-Service, actif depuis la mi-2025). Le groupe a récemment revendiqué une attaque d'envergure contre l'YMCA de Columbia, menaçant d'exfiltrer et de publier des enregistrements médicaux et des dossiers d'adhérents.

Le vecteur d'accès initial privilégié par le groupe consiste à exploiter des vulnérabilités connues sur les équipements d'accès à distance (VPN, firewalls) ou à utiliser des identifiants valides compromis. Une fois l'accès établi, les attaquants initient une phase de contournement agressif des systèmes de défense (Defense Evasion) :
* Utilisation intensive de scripts PowerShell conçus pour désactiver la protection en temps réel, la protection cloud et le service d'envoi d'échantillons de Microsoft Defender.
* Suppression méthodique des journaux d'événements Windows (Event ID 104 et 1102) pour entraver l'analyse forensique.
* Configuration de tunnels réseau proxy SOCKS via des connexions chiffrées SSH pour masquer l'infrastructure de commande et de contrôle (C2), s'appuyant notamment sur l'IP `193[.]233[.]202[.]17`.
* Mouvement latéral et escalade de privilèges via des tâches planifiées malveillantes (`T1053.005`) configurées pour s'exécuter à intervalle régulier sur les contrôleurs de domaine.

---

### Analyse de l'impact

L'impact est particulièrement critique pour les secteurs de la santé et du social (YMCA). Outre le chiffrement complet des données qui provoque un déni de service opérationnel immédiat, l'exfiltration et la menace de divulgation de données de santé exposent les organisations à un chantage réputationnel et à des sanctions réglementaires sévères.

---

### Recommandations

* Activer la "Tamper Protection" au sein de Microsoft Defender de manière centralisée pour interdire sa désactivation par script.
* Restreindre les communications inter-postes (mouvements latéraux) sur les ports RDP (3389) et SMB (445).
* Imposer l'authentification multifacteur (MFA) résistante au phishing sur l'intégralité des accès distants.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Auditer périodiquement les configurations des tâches planifiées sur les serveurs Active Directory.
* Intégrer les signatures réseau de détection du trafic vers l'adresse C2 suspecte.

#### Phase 2 — Détection et analyse
* Rechercher les alertes d'effacement de journaux de sécurité (Event ID 1102).
* **Requête SIEM (Logclear) :**
  `EventID == 1102 OR EventID == 104`
* Identifier l'exécution anormale de commandes PowerShell manipulant la cmdlet `Set-MpPreference`.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le contrôleur de domaine affecté, déconnecter l'accès Internet global de l'infrastructure et tuer les tunnels SOCKS actifs.
* **Éradication :** Supprimer les tâches planifiées malveillantes, éliminer les scripts d'évasion EDR et purger les outils de hacking d'outils comme Mimikatz.
* **Récupération :** Valider l'intégrité des bases Active Directory, restaurer les données à partir de sauvegardes isolées physiquement (hors ligne) et forcer le renouvellement des secrets Kerberos (krbtgt).

#### Phase 4 — Activités post-incident
* Analyser l'étendue exacte des données exfiltrées pour préparer la notification obligatoire RGPD/CNIL ou HIPAA sous 72h.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de désactivation de l'antivirus via PowerShell | T1059.001 | Logs PowerShell (Event ID 4104) | `Set-MpPreference -DisableRealtimeMonitoring $true` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `193[.]233[.]202[.]17` | Adresse IP d'infrastructure C2 SOCKS utilisée par le malware | Haute |
| Hash SHA256 | `f918535f974591ef031bd0f30a8171e3da27a6754e6426a8ba095f83195661c8` | Charge utile de chiffrement / script de désactivation Defender | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1053.005** | Execution | Scheduled Task | Planification de tâches pour forcer l'exécution périodique des agents persistants. |
| **T1059.001** | Execution | PowerShell | Utilisation de scripts d'administration pour forcer l'arrêt des services Defender. |
| **T1078** | Defense Evasion | Valid Accounts | Usage de comptes légitimes détournés pour se déplacer latéralement. |

---

### Sources

* [Huntress Research on The Gentlemen](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps)
* [Mastodon Threat Intel Claims](https://mastodon.social/@Matchbook3469/116613866415964658)

---

<div id="operation-saffron-dismantling-of-first-vpn-infrastructure"></div>

## Operation Saffron - Dismantling of First VPN infrastructure

### Résumé technique

Une opération policière internationale coordonnée par Europol, baptisée "Operation Saffron", a permis le démantèlement complet de l'infrastructure cybercriminelle "First VPN" (opérée via les domaines `1vpns[.]com` et `1vpns[.]org`). Ce service était activement loué par de nombreux opérateurs de rançongiciels pour masquer leurs activités lors des phases de pénétration et d'exfiltration.

L'action répressive a abouti à la saisie de 33 serveurs de transit localisés dans 27 pays et à l'arrestation de l'administrateur présumé du réseau en Ukraine. Le support technique de partenaires industriels tels que Bitdefender a permis d'analyser l'infrastructure pour extraire les journaux de trafic sous-jacents, permettant de rétro-identifier les adresses IP d'origine des attaquants criminels.

---

### Analyse de l'impact

L'impact stratégique est majeur pour l'écosystème cybercriminel. La désactivation de ce réseau d'anonymisation perturbe directement les opérations de plusieurs gangs cybercriminels, tout en fournissant aux forces de l'ordre une masse de métadonnées inestimables pour mener des enquêtes ultérieures.

---

### Recommandations

* Interdire l'installation et l'usage de tout service de VPN commercial ou d'anonymisation non validé par la charte informatique sur le parc d'entreprise.
* Auditer les flux de trafic à la recherche de connexions historiques vers les domaines et serveurs saisis de First VPN.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Intégrer la liste des adresses IP associées aux serveurs saisis par Europol au sein de la liste noire de blocage du proxy réseau d'entreprise.

#### Phase 2 — Détection et analyse
* Analyser l'historique de la télémétrie DNS sur 12 mois pour valider si des postes internes ont communiqué avec l'infrastructure VPN.
* **Requête DNS (SIEM) :**
  `domain == "1vpns.com" OR domain == "1vpns.org"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler logiquement et physiquement tout poste de travail ayant initié des sessions persistantes vers les domaines cibles.
* **Éradication :** Procéder à l'audit complet de la machine concernée pour identifier une éventuelle intrusion masquée par ce tunnel. Purger l'application VPN non autorisée.
* **Récupération :** Restaurer la configuration réseau nominale et forcer la réinitialisation des accès de l'employé.

#### Phase 4 — Activités post-incident
* Collaborer avec les autorités compétentes s'il s'avère qu'un attaquant a exploité ce canal pour cibler l'infrastructure de l'entreprise.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de connexions persistantes sortantes suspectes vers des plages d'IP de transit | T1041 | Logs Proxy / Pare-feu | `destination.domain: "*1vpns*"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `1vpns[.]com` | Domaine officiel du service cybercriminel First VPN | Haute |
| Domaine | `1vpns[.]org` | Domaine secondaire d'infrastructure First VPN | Haute |

---

### TTP MITRE ATT&CK

*Aucun TTP MITRE ATT&CK technique d'intrusion n'est directement rattaché à l'action de démantèlement.*

---

### Sources

* [Security Affairs First VPN Takedown](https://securityaffairs.com/192491/cyber-crime/global-law-enforcement-operation-takes-first-vpn-offline.html)
* [DataBreaches.net Operation Saffron](https://databreaches.net/2026/05/21/operation-saffron-bitdefender-joins-first-vpn-takedown/?pk_campaign=feed&pk_kwd=operation-saffron-bitdefender-joins-first-vpn-takedown)
* [Mastodon Europol Crackdown](https://infosec.exchange/@hackerworkspace/116614014219673741)

---

<div id="teampcp-shai-hulud-supply-chain-campaign-targeting-npm"></div>

## TeamPCP - Shai-Hulud supply chain campaign targeting npm

### Résumé technique

L'équipe Unit 42 de Palo Alto Networks a documenté l'activité et l'évolution du groupe cybercriminel TeamPCP. Ce dernier orchestre des attaques d'envergure sur la chaîne d'approvisionnement via le registre de paquets npm en exploitant un ver automatisé nommé "Shai-Hulud".

La campagne cible particulièrement les développeurs utilisant des outils modernes comme Bun pour empoisonner le cache de compilation des processus de CI/CD (intégration et déploiement continus), notamment chez SAP et TanStack. Le mode opératoire se décline ainsi :
* Propagation automatisée de paquets malveillants usurpant des noms de paquets populaires (typosquatting).
* Injection de code malveillant au moment de la phase de compilation (scripts de pré-installation) pour voler de manière furtive les jetons d'identité OIDC (OpenID Connect) et les identifiants d'accès d'API stockés localement.
* Exfiltration des jetons d'authentification vers le domaine de C2 `t[.]m-kosche[.]com` ou utilisation illégitime du téléchargement de binaires hébergés sur GitHub (`hxxps[://]github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/`).

L'infection se propage sans nécessiter de modification directe du code source apparent du projet victime, contournant ainsi les vérifications de signature standard de niveau SLSA Build Level 3.

---

### Analyse de l'impact

L'impact est extrêmement grave pour les éditeurs de logiciels et les infrastructures cloud associés. Le détournement de secrets d'administration cloud (AWS, Azure, GCP via OIDC) permet aux attaquants de pénétrer directement les environnements de production des clients finaux pour mener de l'exfiltration massive ou des attaques par rançongiciels.

---

### Recommandations

* Configurer les serveurs de build d'applications (runners) pour interdire tout flux réseau sortant vers des destinations non listées (Internet libre).
* Imposer l'usage de registres de paquets privés d'entreprise avec mise en cache locale contrôlée et validation obligatoire par outil de scan SCA (Software Composition Analysis).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Déployer des outils de surveillance d'activité des processus système au sein des conteneurs de compilation CI/CD.
* Configurer le blocage réseau préventif du domaine d'exfiltration cible.

#### Phase 2 — Détection et analyse
* Rechercher les tentatives de connexions non habituelles de la part des gestionnaires de paquets (npm, bun) vers des serveurs externes.
* **Requête EDR (Compilation de code) :**
  `process.name == "node" AND network.destination_ip != "registry.npmjs.org"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Couper immédiatement le pipeline de déploiement affecté, révoquer de manière centralisée toutes les clés API et tokens OIDC générés ou stockés sur les agents de build concernés.
* **Éradication :** Nettoyer le cache local des runners, purger les dépendances malveillantes npm et ré-analyser l'intégrité du code source.
* **Récupération :** Reconstruire l'image du runner à partir d'une source propre certifiée et relancer la compilation sécurisée.

#### Phase 4 — Activités post-incident
* Mener un audit complet des environnements cloud rattachés aux comptes des tokens exfiltrés pour repérer d'éventuelles créations de comptes persistants ou de portes dérobées.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection d'exfiltration de secrets système lors de builds de développement | T1195.001 | Logs de terminaux de build | `process.command_line: "*gh auth token*" OR process.command_line: "*AWS_ACCESS_KEY_ID*"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `t[.]m-kosche[.]com` | Serveur d'exfiltration de secrets et de contrôle du ver Shai-Hulud | Haute |
| URL | `hxxps[://]github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/` | Lien de téléchargement de dépendance détournée par le ver | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1195.001** | Initial Access | Active supply chain compromise | Altération et distribution automatisée de paquets malveillants au sein du registre npm public. |

---

### Sources

* [Unit 42 Supply Chain Attack Analysis](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

---

<div id="kimwolf-botmaster-arrest-dismantling-of-a-major-ddos-botnet"></div>

## Kimwolf botmaster arrest - Dismantling of a major DDoS botnet

### Résumé technique

Une action policière transfrontalière conjointe menée au Canada et aux États-Unis a mené à l'arrestation de Jacob Butler (alias "Dort"), âgé de 23 ans. L'individu est accusé d'être l'administrateur principal (botmaster) du réseau de botnet IoT "Kimwolf".

Ce botnet s'appuyait sur l'enrôlement de millions d'objets connectés vulnérables (routeurs domestiques, caméras IP de surveillance, cadres photo numériques) exposés à l'Internet public et utilisant des identifiants par défaut ou des vulnérabilités de micrologiciels non corrigées. Les capacités de frappe de Kimwolf permettaient de déclencher des attaques par déni de service distribué (DDoS) records atteignant jusqu'à 30 Terabits par seconde (Tbps), ciblant des fournisseurs d'accès Internet, des infrastructures étatiques critiques et des entités publiques.

---

### Analyse de l'impact

L'arrestation du botmaster et la neutralisation concomitante de ses serveurs de commande centraux affaiblissent grandement les capacités DDoS disponibles sur les marchés cybercriminels, améliorant temporairement la résilience réseau des parcs d'infrastructures.

---

### Recommandations

* Désactiver impérativement le protocole UPnP (Universal Plug and Play) sur l'ensemble des modems et routeurs externes d'accès à Internet.
* Changer systématiquement les identifiants d'administration d'usine de tous les périphériques IoT et limiter leur connectivité réseau directe avec l'Internet public.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Déployer une solution de protection et d'atténuation DDoS robuste (Scrubbing Centers) auprès de votre opérateur d'accès Internet.

#### Phase 2 — Détection et analyse
* Surveiller les hausses soudaines et inexpliquées d'utilisation de la bande passante sur les liaisons Internet principales de l'organisation.
* **Analyse de trafic (Netflow) :** Identifier les vagues massives de requêtes SYN ou UDP issues de multiples adresses IP géographiquement dispersées.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Activer les politiques d'atténuation DDoS au niveau du CDN ou du fournisseur de transit Internet (BGP Blackholing ou redirection du trafic).
* **Éradication :** Pour les routeurs internes potentiellement compromis par le botnet, appliquer une réinitialisation d'usine complète et appliquer le dernier micrologiciel de sécurité.
* **Récupération :** Valider le retour progressif des temps de latence nominaux et rouvrir les accès applicatifs.

#### Phase 4 — Activités post-incident
* Analyser les types de paquets DDoS reçus pour adapter les règles de filtrage préventif sur les pare-feux périmétriques.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de périphériques IoT effectuant des connexions sortantes suspectes | T1584.005 | Logs pare-feu (flux sortants IoT) | `source_ip.category: "IoT" AND port: 23 OR port: 8080` |

---

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun indicateur de compromission technique de C2 individuel n'est documenté dans l'avis judiciaire.*

---

### TTP MITRE ATT&CK

*Aucun TTP MITRE ATT&CK d'intrusion n'est directement rattaché à l'action de démantèlement du botnet.*

---

### Sources

* [KrebsOnSecurity Kimwolf Botmaster Arrest](https://krebsonsecurity.com/2026/05/alleged-kimwolf-botmaster-dort-arrested-charged-in-u-s-and-canada/)

---

<div id="github-repository-compromise-via-malicious-vscode-extension"></div>

## GitHub repository compromise via malicious VSCode extension

### Résumé technique

Le service de sécurité de GitHub a confirmé la compromission de plus de 3 800 dépôts de code source privés et publics. L'intrusion s'est déroulée à travers un vecteur d'attaque novateur basé sur l'usage d'une extension malveillante hébergée sur le catalogue officiel d'extensions de l'éditeur Visual Studio Code (VSCode).

Lorsqu'elle était installée par des développeurs, l'extension réalisait les actions suivantes :
* Extraction silencieuse des jetons d'authentification API de GitHub et des identifiants d'accès SSH stockés localement sur le poste de développement.
* Exfiltration de ces secrets de connexion vers des serveurs de commande externes contrôlés par l'attaquant.
* Utilisation automatisée des identifiants compromis par des scripts côté attaquant pour télécharger l'intégralité du code source des projets gérés par les victimes.

L'analyse de l'écosystème met en évidence les faiblesses inhérentes à la validation automatique des extensions d'IDE tierces.

---

### Analyse de l'impact

L'impact est direct pour la propriété intellectuelle des organisations concernées. L'exfiltration de code source propriétaire expose l'entreprise au vol de technologies brevetées ou à l'analyse proactive par des attaquants cherchant à découvrir des failles applicatives ("zero-days") au sein du code pour mener des cyberattaques ultérieures.

---

### Recommandations

* Interdire l'installation d'extensions VSCode ou d'outils d'IDE non validés par l'équipe de sécurité de l'entreprise.
* Imposer l'authentification à double facteur obligatoire pour toutes les connexions aux dépôts GitHub d'entreprise.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre en œuvre un mécanisme d'inventaire automatique des extensions VSCode installées sur les parcs de machines de développement.

#### Phase 2 — Détection et analyse
* Surveiller les logs de connexion à la plateforme GitHub à la recherche de clonages de dépôts massifs ou d'accès d'API inhabituels hors des heures ouvrées.
* **Requête d'audit GitHub :**
  `action == "repo.download" AND user_agent != "git*"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Révoquer d'urgence l'ensemble des clés d'accès personnelles (Personal Access Tokens), les clés SSH et les sessions actives du développeur compromis sur GitHub.
* **Éradication :** Forcer la désinstallation de l'extension corrompue et isoler temporairement le poste pour analyse forensique.
* **Récupération :** Re-générer de nouvelles clés d'accès après s'être assuré de l'absence de persistance malveillante locale.

#### Phase 4 — Activités post-incident
* Examiner l'historique d'audit de GitHub pour cartographier précisément l'ensemble des dépôts clonés de manière illégitime par l'attaquant.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exfiltration de secrets de configuration d'IDE | T1195.001 | Logs de processus locaux | `process.parent_name: "code" AND file.path: "*.git-credentials*"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

*Aucune signature de fichier ou domaine d'exfiltration spécifique de l'extension VSCode n'est actuellement publié par GitHub.*

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1195.001** | Initial Access | Active supply chain compromise | Compromission d'une extension officielle de l'éditeur pour exfiltrer les accès locaux. |

---

### Sources

* [DataBreaches.net GitHub VSCode Breach Confirm](https://databreaches.net/2026/05/21/github-confirms-breach-of-3800-repos-via-malicious-vscode-extension/)

---

<div id="wanttocry-ransomware-exploitation-of-exposed-smb-shares"></div>

## WantToCry ransomware - Exploitation of exposed SMB shares

### Résumé technique

Une nouvelle vague d'infections orchestrée par le rançongiciel "WantToCry" cible activement les serveurs et les équipements de stockage connectés (NAS) exposés de manière imprudente à l'Internet public. 

Cette campagne n'a pas besoin de déployer ou d'exécuter un binaire malveillant directement sur la machine victime pour chiffrer ses fichiers. À la place, les attaquants tirent parti du protocole d'administration à distance SMB (Server Message Block) :
* Recherche automatisée d'équipements exposant le port 445 SMB.
* Tentative d'accès en force (brute-force) ou exploitation de mots de passe d'administration par défaut ou de faible complexité sur les partages réseau.
* Connexion à distance aux volumes partagés et chiffrement direct des documents à la volée à travers le canal SMB monté.
* Renommage systématique des fichiers chiffrés avec l'extension malveillante `[.]want_to_cry`.

---

### Analyse de l'impact

L'impact est immédiat pour la continuité d'activité opérationnelle. Les serveurs de fichiers partagés d'entreprise ou les sauvegardes hébergées sur des volumes NAS mal configurés sont rendus totalement indisponibles, paralysant l'activité de l'entreprise en quelques minutes.

---

### Recommandations

* Interdire formellement toute exposition directe du port 445 SMB sur l'Internet public via des règles de filtrage strictes au niveau du pare-feu périmétrique.
* Désactiver impérativement les protocoles obsolètes SMBv1 et forcer l'usage de connexions SMB chiffrées (SMBv3) avec authentification robuste.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre en œuvre des audits réguliers d'exposition de la surface externe à l'aide d'outils de scan de ports.
* Configurer des sauvegardes immuables (hors ligne ou sur volumes en lecture seule) de l'ensemble des partages réseau.

#### Phase 2 — Détection et analyse
* Surveiller les pointes de trafic réseau sur le port 445 et l'apparition de volumes d'erreurs d'accès anormaux.
* **Détection SIEM (Renommagements de fichiers) :**
  `file.extension == "want_to_cry"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le volume réseau ou le NAS affecté en coupant les interfaces d'accès réseau pour stopper instantanément la propagation du chiffrement distant. Bloquer l'IP externe attaquante.
* **Éradication :** Identifier et désactiver le compte utilisateur compromis ayant servi à monter la connexion SMB malveillante.
* **Récupération :** Valider l'intégrité des structures système et restaurer les fichiers à partir de sauvegardes saines préalablement validées.

#### Phase 4 — Activités post-incident
* Conduire une révision complète des politiques de gestion de mots de passe d'administration des périphériques connectés.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de connexions réseau SMB suspectes hors périmètre interne | T1135 | Logs réseau pare-feu | `destination.port: 445 AND source.ip != "internal_subnet"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Extension de fichier | `[.]want_to_cry` | Extension apposée sur les fichiers chiffrés par le ransomware | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1135** | Discovery | Network Share Discovery | Recherche active de partages réseau exposés pour localiser les fichiers cibles à chiffrer. |

---

### Sources

* [AlienVault OTX WantToCry Threat Brief](https://social.raytec.co/@techbot/116615530759805235)

---

<div id="us-healthcare-external-attack-surface-analysis-and-ot-exposure"></div>

## US Healthcare - External attack surface analysis and OT exposure

### Résumé technique

Une analyse de la surface d'attaque externe globale du secteur de la santé aux États-Unis, menée par les équipes de Flare, a mis en évidence une exposition critique de systèmes internes et industriels directement accessibles depuis l'Internet public. 

L'inventaire réalisé révèle la présence de **15 885 serveurs et équipements exposés**, présentant des faiblesses d'envergure :
* Exposition de protocoles de gestion de bas niveau matériels non sécurisés (ports ouverts pour l'administration de type Telnet ou HTTP sans chiffrement).
* Présence d'équipements de contrôle industriel (OT), notamment des automates programmables industriels (PLCs) Rockwell Automation et Allen-Bradley. Ces derniers sont activement recherchés par des groupes d'intérêt étatiques comme CyberAv3ngers (affiliés à l'Iran) pour mener des actions perturbatrices.
* Des passerelles VPN et pare-feux non mis à jour présentant des failles d'accès à distance connues de longue date.

Cette exposition massive offre aux attaquants un moyen d'effectuer des reconnaissances préalables automatisées à l'aide d'outils d'indexation comme Shodan ou Censys.

---

### Analyse de l'impact

L'impact est majeur pour la sécurité physique des patients et des infrastructures. Au-delà du risque classique de vol de bases de données, la prise de contrôle d'équipements industriels de gestion des bâtiments hospitaliers (climatisation, traitement des eaux, générateurs de secours) peut provoquer une interruption physique des soins de santé et mettre en danger des vies humaines.

---

### Recommandations

* Réduire drastiquement la surface d'exposition externe en interdisant tout accès d'administration direct (RDP, VNC, Telnet) et en plaçant les équipements derrière un pare-feu restrictif.
* Isoler hermétiquement le réseau industriel (OT) du réseau bureautique et informatique (IT) de l'établissement.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Réaliser une cartographie mensuelle automatique de la surface d'attaque externe à l'aide d'outils de détection d'exposition (ASM).
* Mettre hors ligne les interfaces d'administration industrielle accessibles par Internet.

#### Phase 2 — Détection et analyse
* Surveiller l'apparition de flux réseau suspects ciblant des ports industriels standards (comme le port CIP 44818 ou le port VNC 5900).
* **Requête SIEM (Scans externes) :**
  `port == 44818 OR port == 5900`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Fermer immédiatement le port d'accès sur le pare-feu externe et révoquer les sessions VPN actives douteuses.
* **Éradication :** Mettre à jour les micrologiciels des automates exposés et changer l'intégralité des identifiants d'usine par des secrets robustes.
* **Récupération :** Réinitialiser les services réseau et s'assurer de la fermeture effective de l'exposition.

#### Phase 4 — Activités post-incident
* Conduire une session de retour d'expérience avec les équipes de gestion technique des bâtiments pour intégrer la cybersécurité dans les déploiements physiques.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de requêtes d'exploration et de scans sur les protocoles industriels exposés | T1580 | Logs pare-feu réseau | `destination.port: 44818 AND action: "accept"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun indicateur d'infrastructure C2 individuel n'est directement rattaché à ce rapport de surface d'attaque sectorielle.*

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1580** | Reconnaissance | Cloud Infrastructure Discovery | Recherche d'infrastructures informatiques exposées à l'aide d'outils automatisés de scan. |

---

### Sources

* [Flare US Healthcare External Attack Surface Analysis](https://flare.io/learn/resources/blog/us-healthcare-sector-wide-external-attack-surface-analysis)

---

<div id="cisco-talos-badiis-malware-and-seo-fraud-campaigns"></div>

## Cisco Talos - BadIIS malware and SEO fraud campaigns

### Résumé technique

Les équipes d'analyse de menaces de Cisco Talos ont documenté l'évolution de la suite de malwares commerciaux connue sous le nom de "BadIIS". Ces implants sont activement vendus au sein de forums cybercriminels sinophones et ciblent spécifiquement les serveurs Web hébergés sous IIS (Internet Information Services) de Microsoft.

Une fois que les attaquants ont obtenu un accès initial par exploitation de failles d'applications Web, ils installent un composant d'extension de serveur malveillant (IIS Module) :
* Ce module malveillant s'injecte de manière transparente au sein de la chaîne de traitement des requêtes HTTP du serveur IIS.
* Il analyse le champ "User-Agent" de chaque connexion entrante. S'il détecte que la requête provient d'un moteur de recherche légitime (comme Googlebot ou Bingbot), il modifie dynamiquement le code HTML de la réponse pour y insérer des mots-clés et des liens illicites (fraude SEO).
* Si le visiteur est un utilisateur classique, la page normale est affichée pour masquer l'infection.
* Ce mécanisme inclut également des modules d'exfiltration furtive utilisant des chaînes de débogage cachées, s'appuyant notamment sur des signatures associées à des fichiers `.pdb` de compilation de type `demo.pdb`.

---

### Analyse de l'impact

L'impact opérationnel affecte la réputation numérique de l'organisation ciblée. Le détournement SEO peut conduire au déréférencement total ou partiel du site officiel de l'entreprise par les moteurs de recherche, perturbant gravement ses canaux d'acquisition commerciaux et son image de marque.

---

### Recommandations

* Auditer régulièrement les modules et extensions IIS installés sur l'ensemble des serveurs Web d'entreprise à l'aide de l'outil en ligne de commande `appcmd`.
* Restreindre les privilèges du processus applicatif Web IIS (`IIS_IUSRS`) pour empêcher toute installation d'extensions système sans élévation de privilèges d'administrateur local.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Établir un inventaire rigoureux des configurations nominales des modules IIS autorisés.
* Configurer la centralisation des journaux de configuration IIS (Web.config et applicationHost.config).

#### Phase 2 — Détection et analyse
* Détecter les modifications inattendues des fichiers de configuration IIS ou l'ajout de DLL non référencées au sein du dossier de chargement des modules.
* **Commande IIS d'audit :**
  `appcmd list modules`
* Analyser les logs HTTP à la recherche de redirections inexpliquées lorsque l'User-Agent est modifié pour simuler un moteur de recherche.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Placer le serveur Web concerné hors ligne, rediriger temporairement le trafic légitime vers une page statique sécurisée et isoler l'hôte.
* **Éradication :** Retirer le module IIS malveillant via la console d'administration, supprimer physiquement la DLL correspondante et restaurer les fichiers de configuration sains.
* **Récupération :** Corriger la vulnérabilité d'origine de l'application Web ayant permis l'intrusion initiale et remettre le site en production.

#### Phase 4 — Activités post-incident
* Soumettre une demande de réévaluation de sécurité aux moteurs de recherche si le domaine a été signalé comme corrompu ou malveillant.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de chargements de modules IIS non autorisés | T1105 | Journaux d'activité IIS / Process creation | `file.path: "*\\system32\\inetsrv\\*" AND file.name: "*.dll" AND file.owner != "TrustedInstaller"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Hash SHA256 | `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507` | Fichier DLL correspondant au module malveillant BadIIS | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1105** | Command and Control | Ingress Tool Transfer | Transfert et chargement de la bibliothèque IIS malveillante sur le serveur web victime. |

---

### Sources

* [Cisco Talos - The Art of Being Ungovernable](https://blog.talosintelligence.com/the-art-of-being-ungovernable/)
* [Mastodon Share HackerWorkspace](https://infosec.exchange/@hackerworkspace/116613997900018534)

---

<div id="interpol-cyber-operation-takedown-of-phishing-infrastructure-in-morocco"></div>

## Interpol cyber operation - Takedown of phishing infrastructure in Morocco

### Résumé technique

Une opération de police d'envergure, menée sous l'égide de l'organisation INTERPOL avec l'assistance technique étroite d'éditeurs industriels spécialisés (Kaspersky et Group-IB), a ciblé les réseaux de cybercriminalité actifs au Maroc. 

Cette opération visait la neutralisation systématique de serveurs de commande de botnets de phishing (hameçonnage). Les attaquants opéraient à l'aide de trousses de phishing (phishing kits) sophistiquées imitant des services gouvernementaux et des institutions bancaires européennes. Les données de télémétrie réseau partagées par les partenaires privés ont permis d'identifier et de désactiver les nœuds de commande et de géolocaliser les opérateurs impliqués.

---

### Analyse de l'impact

L'impact stratégique réside dans le démantèlement d'importantes infrastructures de distribution de campagnes de phishing. Cette neutralisation collective limite temporairement la prolifération d'escroqueries bancaires ciblant la population francophone et européenne.

---

### Recommandations

* Bloquer de manière préventive les nouvelles résolutions DNS de domaines enregistrés récemment (moins de 72h) sur les serveurs de noms de l'organisation.
* Éduquer et tester régulièrement les collaborateurs via des campagnes de simulation de phishing réalistes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* S'assurer de la réception en temps réel de flux d'intelligence des menaces (Threat Intelligence feeds) intégrant les domaines de phishing fraîchement découverts.

#### Phase 2 — Détection et analyse
* Surveiller la réception d'e-mails d'origine externe présentant des schémas de liens redirigeant vers des domaines inconnus ou suspects.
* **Requête SIEM (Accès proxy) :**
  `url.domain != "trusted_domains" AND email.has_link == true`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Bloquer immédiatement l'accès au domaine de phishing identifié au niveau du pare-feu et du proxy réseau. Supprimer l'e-mail du serveur de messagerie pour tous les utilisateurs.
* **Éradication :** Révoquer les sessions actives de tout utilisateur ayant cliqué sur le lien et saisi ses identifiants.
* **Récupération :** Forcer la réinitialisation de l'authentification multifacteur et modifier le mot de passe de l'utilisateur affecté.

#### Phase 4 — Activités post-incident
* Partager les caractéristiques techniques de la trousse de phishing découverte avec la communauté de sécurité ou les autorités de signalement officielles.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'utilisateurs s'étant connectés sur des domaines de phishing émulés | T1567 | Logs Proxy Web | `url.path: "*login*" AND destination.domain != "trusted_idp"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

*Aucune adresse de serveur ou nom de domaine de phishing spécifique n'est actuellement publié par INTERPOL.*

---

### TTP MITRE ATT&CK

*Aucun TTP MITRE ATT&CK technique d'intrusion n'est directement rattaché à ce rapport d'opération policière globale.*

---

### Sources

* [Kaspersky and Group-IB INTERPOL Operation](https://databreaches.net/2026/05/21/kaspersky-group-ib-detail-role-in-interpol-cyber-operation-involving-morocco/?pk_campaign=feed&pk_kwd=kaspersky-group-ib-detail-role-in-interpol-cyber-operation-involving-morocco)

---

<div id="identity-and-access-management-risks-of-active-credentials-for-former-employees"></div>

## Identity and Access Management - Risks of active credentials for former employees

### Résumé technique

Les rapports techniques d'incident partagés rappellent une faille organisationnelle majeure liée à la gestion du cycle de vie des identités et des accès (IAM) : la persistance d'identifiants et de comptes actifs appartenant à d'anciens collaborateurs (insider threat).

L'absence d'automatisation et de coordination stricte entre les services de ressources humaines (RH) et les équipes d'administration informatique permet le maintien de comptes d'accès VPN ou de profils cloud d'anciens employés. Des attaquants opportunistes ou des collaborateurs mécontents tirent parti de ces identifiants valides non révoqués pour s'introduire sur l'infrastructure de l'entreprise sous le couvert de comptes légitimes. Ce vecteur d'accès ne déclenche généralement aucune alerte de sécurité standard car il exploite des comptes déjà configurés et autorisés.

---

### Analyse de l'impact

L'impact opérationnel peut être catastrophique, allant de la suppression malveillante de sauvegardes et de bases de données de production par un ancien salarié mécontent au vol et à l'exfiltration de propriété intellectuelle industrielle au profit de tiers concurrents.

---

### Recommandations

* Automatiser la désactivation des accès informatiques en synchronisant directement l'annuaire de gestion des identités (Active Directory / Okta) avec le logiciel de paie et de gestion des ressources humaines de l'entreprise.
* Conduire des revues d'accès logiques trimestrielles de l'intégralité des comptes à privilèges élevés et des profils d'accès VPN actifs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Définir une procédure d'offboarding informatique obligatoire, documentée et validée par une fiche de contrôle pour chaque départ d'employé.

#### Phase 2 — Détection et analyse
* Détecter les tentatives de connexions initiées par des comptes d'anciens collaborateurs répertoriés.
* **Requête SIEM (Comptes inactifs) :**
  `event.action == "login" AND user.status == "disabled" OR user.status == "terminated"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Désactiver immédiatement le compte d'accès concerné de manière globale au niveau de l'Active Directory et révoquer l'intégralité de ses jetons d'authentification cloud (OAuth).
* **Éradication :** Identifier et détruire toute clé API persistante ou clé SSH publique générée et associée à ce profil de compte.
* **Récupération :** Valider l'intégrité des données accédées par ce compte durant ses dernières sessions et fermer définitivement le profil de connexion.

#### Phase 4 — Activités post-incident
* Réaliser une analyse des processus de départ des collaborateurs pour corriger la faille de transmission administrative à l'origine de l'oubli.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'activités réseau initiées par des comptes obsolètes non purgés | T1078.004 | Logs de connexion Active Directory / IAM | `user.termination_date < sysdate AND event.action: "successful_login"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

*Aucune signature de malware ou IP de C2 spécifique n'est applicable à cette faille organisationnelle.*

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1078.004** | Defense Evasion | Cloud Accounts | Utilisation de comptes cloud légitimes non révoqués appartenant à d'anciens collaborateurs pour s'infiltrer. |

---

### Sources

* [DataBreaches.net - Remind to Terminate Credentials](https://databreaches.net/2026/05/21/todays-reminder-to-terminate-employees-credentials-when-their-employment-ends/?pk_campaign=feed&pk_kwd=todays-reminder-to-terminate-employees-credentials-when-their-employment-ends)

---

<div id="financial-scams-proliferation-of-fraudulent-ads-on-social-media"></div>

## Financial Scams - Proliferation of fraudulent ads on social media

### Résumé technique

Les associations de protection des consommateurs européennes ont déposé des plaintes coordonnées concernant la prolifération de près de 900 publicités frauduleuses de placements financiers et de prêts à taux usuraires diffusées de manière massive sur les réseaux sociaux (Meta, Google et TikTok).

L'analyse technique de ces campagnes de distribution d'escroqueries (malvertising et social-engineering) démontre que les attaquants exploitent les faiblesses des systèmes de modération publicitaire automatisée :
* Enregistrement de comptes de diffuseurs publicitaires usurpant des identités d'entreprises financières légitimes.
* Utilisation de techniques d'aiguillage dynamique de trafic (cloaking) : l'API de validation du réseau publicitaire se voit présenter un contenu informatif légitime, tandis que l'utilisateur final mobile est redirigé vers une page d'hameçonnage visant à lui dérober ses informations bancaires ou à lui faire installer des chevaux de Troie bancaires.
* Collecte de données d'identité personnelles ré-injectées dans des schémas complexes d'arnaques au faux conseiller bancaire.

---

### Analyse de l'impact

L'impact financier pour les victimes est considérable, avec des pertes cumulées estimées à 4,2 milliards d'euros pour les citoyens européens. Pour les marques usurpées par ces publicités malveillantes, l'impact se traduit par une baisse significative de la confiance des clients et une dégradation réputationnelle sévère.

---

### Recommandations

* Déployer des extensions de blocage de publicités (Adblockers) robustes et centralisées sur l'ensemble du parc de navigateurs Web de l'entreprise.
* Établir une cellule de veille réputationnelle pour identifier proactivement l'apparition de fausses campagnes ou d'usurpations de l'identité de l'entreprise sur les plateformes publicitaires.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* S'assurer de l'implémentation de règles de filtrage DNS bloquant l'accès aux réseaux d'aiguillage de trafic (Ad-networks suspects).

#### Phase 2 — Détection et analyse
* Surveiller les requêtes réseau internes à la recherche de redirections inexpliquées vers des domaines non catégorisés suite à des clics sur des liens sponsorisés.
* **Analyse EDR (Redirections de clics) :**
  `process.name == "chrome.exe" AND network.destination_ip == "ad_cloaker_subnet"`

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le poste de travail de l'utilisateur ayant interagi avec la publicité frauduleuse et révoquer immédiatement ses identifiants de messagerie et d'outils internes.
* **Éradication :** Procéder à l'analyse de sécurité approfondie du poste à la recherche de logiciels de contrôle à distance non autorisés. Soumettre une alerte de signalement de la publicité à la régie publicitaire concernée.
* **Récupération :** Restaurer la configuration système d'origine et forcer le changement de mots de passe de tous les accès personnels et professionnels de l'employé.

#### Phase 4 — Activités post-incident
* Publier des alertes préventives auprès de l'ensemble du personnel pour les mettre en garde contre les sollicitations téléphoniques d'arnaques à la suite de la saisie de données personnelles sur ces sites.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de clics d'utilisateurs sur des réseaux publicitaires malveillants | T1567 | Logs DNS du proxy d'entreprise | `url.domain: "*clickserve*" OR url.domain: "*doubleclick*"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

*Aucune signature de binaire malveillant ou domaine d'exfiltration universel n'est publié, l'infrastructure d'aiguillage publicitaire étant hautement volatile.*

---

### TTP MITRE ATT&CK

*Aucun TTP MITRE ATT&CK d'intrusion n'est directement rattaché aux campagnes d'escroqueries publicitaires volatiles.*

---

### Sources

* [Le Monde - Arnaques Financières et Associations](https://www.lemonde.fr/pixels/article/2026/05/21/arnaques-financieres-en-ligne-des-associations-de-consommateurs-exigent-des-actions_6691867_4408996.html)

---

<!--
CONTRÔLE FINAL

1. ☐ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. ☐ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. ☐ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. ☐ Tous les IoC sont en mode DEFANG : [Vérifié]
5. ☐ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. ☐ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. ☐ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. ☐ Toutes les sections attendues sont présentes : [Vérifié]
9. ☐ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. ☐ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. ☐ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" — aucun article sans URL complète ne figure dans les synthèses ou la section "Articles" : [Vérifié]
12. ☐ Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13. ☐ Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : Phase 1 — Préparation, Phase 2 — Détection et analyse, Phase 3 — Confinement, éradication et récupération, Phase 4 — Activités post-incident, Phase 5 — Threat Hunting (proactif) : [Vérifié]
14. ☐ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->