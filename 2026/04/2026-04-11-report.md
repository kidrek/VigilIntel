# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités](#synthese-des-vulnerabilites)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [Supply chain attack at cpuid pushes malware with cpu-z hwmonitor](#supply-chain-attack-at-cpuid-pushes-malware-with-cpu-z-hwmonitor)
  * [Nearly 4000 us industrial devices exposed to iranian cyberattacks](#nearly-4000-us-industrial-devices-exposed-to-iranian-cyberattacks)
  * [Analysis of one billion cisa kev remediation records](#analysis-of-one-billion-cisa-kev-remediation-records)
  * [Microsoft canadian employees targeted in payroll pirate attacks](#microsoft-canadian-employees-targeted-in-payroll-pirate-attacks)
  * [Uat-10362 linked to lucidrook attacks targeting taiwan](#uat-10362-linked-to-lucidrook-attacks-targeting-taiwan)
  * [Unc6783 uses fake zendesk and okta pages to bypass mfa](#unc6783-uses-fake-zendesk-and-okta-pages-to-bypass-mfa)
  * [Potential adobe reader zero-day reported](#potential-adobe-reader-zero-day-reported)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel des menaces cyber est marqué par une accélération sans précédent du cycle d'exploitation, où le temps moyen de remédiation (souvent mesuré en saisons) est totalement dépassé par la vélocité des attaquants (mesurée en heures). L'industrialisation de l'exploitation, dopée par l'automatisation et l'IA, réduit la fenêtre de correctif à une valeur parfois négative, les vulnérabilités étant exploitées avant même leur divulgation officielle. Parallèlement, les infrastructures critiques occidentales, notamment les automates industriels (PLC), font l'objet d'un ciblage stratégique accru par des acteurs étatiques iraniens dans un contexte de tensions géopolitiques mondiales. Les attaques de la "Supply Chain", illustrées par le compromis de l'API de CPUID, confirment que les outils d'administration et de diagnostic restent des vecteurs privilégiés pour infecter massivement des parcs informatiques. Les techniques d'Adversary-in-the-Middle (AiTM) et de détournement de sessions MFA se normalisent, rendant les méthodes d'authentification classiques obsolètes face à des groupes comme Storm-2755. Le secteur de la santé subit une pression constante avec des attaques par rançongiciel (ChipSoft, Signature Healthcare) provoquant des ruptures de soins critiques en Europe et aux États-Unis. On observe également une professionnalisation des campagnes d'ingénierie sociale ciblant les services de support (Zendesk, Okta) pour l'exfiltration de données massives. Enfin, la fuite de données de grands cabinets d'avocats par le groupe SRG souligne la volonté des attaquants de monétiser la confidentialité juridique par l'extorsion pure. La résilience passera par l'adoption de modèles d'opérations de risque autonomes et une hygiène stricte de la surface d'exposition internet.

<br>
<br>
<div id="syntheses"></div>
<br/>

# Synthèses
<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants
Voici un tableau récapitulatif des acteurs malveillants identifiés :
| Nom de l'acteur | Secteur d'activité ciblé | Mode opératoire privilégié | Source(s)/Url(s) |
|:---|:---|:---|:---|
| CyberAv3ngers | Infrastructures critiques (Eau, Énergie) | Exploitation de PLC Unitronics et Rockwell Automation | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Handala Hack | Santé, Gouvernement, Tech | Wiper, abus d'Intune MDM, exfiltration de données | [Field Effect](https://fieldeffect.com/blog/fake-zendesk-okta-pages-to-bypass-mfa) |
| MuddyWater (MOIS) | Défense, Aérospatiale | Framework CastleRAT, malware ChainShell (blockchain) | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Silent Ransom Group (SRG) | Juridique (Cabinets d'avocats) | Social engineering, phishing, extorsion sans malware | [DataBreaches](https://databreaches.net/2026/04/10/silent-ransom-group-leaked-another-big-law-firm-orrick-herrington-sutcliffe/) |
| Storm-2755 | Ressources Humaines, Finance | AiTM, empoisonnement SEO, vol de tokens MFA | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-canadian-employees-targeted-in-payroll-pirate-attacks/) |
| UAT-10362 | ONG, Universités (Taïwan) | Phishing, malware LucidRook (Lua), DLL Sideloading | [Security Affairs](https://securityaffairs.com/190598/security/uat-10362-linked-to-lucidrook-attacks-targeting-taiwan-based-institutions.html) |
| UNC6783 (alias Raccoon) | Support client (Zendesk, Okta) | Social engineering via live chat, vol de presse-papier | [Field Effect](https://fieldeffect.com/blog/fake-zendesk-okta-pages-to-bypass-mfa) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Tech | Chine vs Inde | Red Hat ferme ses activités d'ingénierie en Chine pour les relocaliser en Inde, par crainte de l'espionnage industriel. | [The Register](https://go.theregister.com/i/cfa/https://www.theregister.com/2026/04/10/red_hat_ends_china_engineering/) |
| Gouvernement | France vs Privacy | GrapheneOS quitte le marché français suite à une campagne de dénigrement et des pressions de la police française sur le chiffrement. | [Nordic Times](https://nordictimes.com/tech/grapheneos-exits-france-after-threats-and-smear-campaign/) |
| Gouvernement | Russie vs Europe | Campagnes de désinformation russes ciblant les élections en Bulgarie, Hongrie et Arménie pour affaiblir l'unité européenne. | [EUvsDisinfo](https://euvsdisinfo.eu/the-kremlin-points-at-ukraine-as-a-threat-for-the-baltic-states-and-accuses-the-eu-with-meddling-in-upcoming-elections/) |
| Infrastructures | Iran vs Israël/USA | Intensification des cyberattaques sur les systèmes de contrôle industriel (ICS) dans le cadre du conflit militaire. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Security Slam 2026 | Stacey Potter | 10/04/2026 | Internationale | Open Source Security Baseline | Projet visant à sécuriser l'écosystème open source via des évaluations de conformité. | [OpenSSF](https://openssf.org/blog/2026/04/10/security-slam-2026-celebrating-our-security-champions-and-project-milestones/) |
| Registre national des cancers | Collectif Santé | 10/04/2026 | France | Décret du 26/12/2025 | Critique sur la collecte massive de données sensibles et l'atteinte à la vie privée par l'Institut national du cancer. | [Le Monde](https://www.lemonde.fr/idees/article/2026/04/10/le-registre-national-des-cancers-constitue-un-fourre-tout-heterogene-de-donnees-sensibles-couvrant-de-multiples-facettes-de-la-vie-privee_6678770_3232.html) |
| Gmail End-to-End Encryption | Sergiu Gatlan | 10/04/2026 | Internationale | Client-Side Encryption (CSE) | Déploiement du chiffrement de bout en bout sur mobile pour les licences Google Workspace Enterprise. | [BleepingComputer](https://www.bleepingcomputer.com/news/google/google-rolls-out-gmail-end-to-end-encryption-on-mobile-devices/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Finance | Bitcoin Depot | Vol de 50.9 BTC (3.6M$) via un compromis de comptes de règlement. | [Security Affairs](https://securityaffairs.com/190578/cyber-crime/bitcoin-depot-hack-leads-to-3-6m-bitcoin-theft-via-stolen-credentials.html) |
| Juridique | Orrick, Herrington & Sutcliffe | Exfiltration massive de fichiers clients et employés confidentiels par SRG suite à un échec de négociation. | [DataBreaches](https://databreaches.net/2026/04/10/silent-ransom-group-leaked-another-big-law-firm-orrick-herrington-sutcliffe/) |
| Santé | ChipSoft | Rançonnement du fournisseur d'EHR, impactant des dizaines d'hôpitaux aux Pays-Bas et en Belgique. | [Security Affairs](https://securityaffairs.com/190615/cyber-crime/ransomware-attack-on-chipsoft-knocks-ehr-services-offline-across-hospitals-in-the-netherlands-and-belgium.html) |
| Santé | Signature Healthcare | Attaque réseau forçant la diversion des ambulances et la fermeture des pharmacies à Brockton. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-40175 | 10.0 | N/A | FALSE | Axios | Prototype Pollution / RCE | T1190: Exploit Public-Facing Application | Permet une escalade vers l'exécution de code ou le compromis complet du cloud via AWS IMDSv2. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40175) |
| CVE-2026-4149 | 10.0 | N/A | FALSE | Sonos Era 300 | Out-of-bounds Access | T1210: Exploitation of Remote Services | Vulnérabilité critique dans la gestion des réponses SMB permettant une exécution de code au niveau noyau. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4149) |
| CVE-2026-5059 | 9.8 | N/A | FALSE | aws-mcp-server | Command Injection | T1203: Exploitation for Client Execution | Injection de commande via AWS CLI permettant l'exécution de code arbitraire sans authentification. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5059) |
| CVE-2025-59528 | N/A | N/A | FALSE | Flowise | RCE | Non mentionnées | Exploitation d'une faille critique permettant l'exécution de code à distance. | [Security Affairs](https://securityaffairs.com/190615/cyber-crime/ransomware-attack-on-chipsoft-knocks-ehr-services-offline-across-hospitals-in-the-netherlands-and-belgium.html) |
| CVE-2026-40189 | 9.3 | N/A | FALSE | goshs | Auth Bypass | T1548: Abuse Elevation Control Mechanism | Permet de supprimer le fichier ACL pour accéder au contenu protégé. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40189) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Analysis of one billion CISA KEV remediation records | Analyse stratégique majeure sur l'accélération de l'exploitation. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/analysis-of-one-billion-cisa-kev-remediation-records-exposes-limits-of-human-scale-security/) |
| CPUID hacked to deliver malware | Attaque supply chain sur des outils de diagnostic populaires. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/supply-chain-attack-at-cpuid-pushes-malware-with-cpu-z-hwmonitor/) |
| Microsoft: Canadian employees targeted in payroll pirate attacks | Détails opérationnels sur les techniques AiTM et contournement MFA. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-canadian-employees-targeted-in-payroll-pirate-attacks/) |
| Nearly 4,000 US industrial devices exposed | Menace critique sur les infrastructures industrielles (OT). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/nearly-4-000-us-industrial-devices-exposed-to-iranian-cyberattacks/) |
| Potential Adobe Reader Zero-Day | Alerte sur une vulnérabilité zero-day potentielle en cours d'exploitation. | [Field Effect](https://fieldeffect.com/blog/researcher-reports-potential-adobe-reader-zero-day) |
| UAT-10362 linked to LucidRook attacks | Détails sur une nouvelle campagne APT sophistiquée à Taïwan. | [Security Affairs](https://securityaffairs.com/190598/security/uat-10362-linked-to-lucidrook-attacks-targeting-taiwan-based-institutions.html) |
| UNC6783 Uses Fake Zendesk and Okta Pages | Analyse des méthodes de social engineering ciblant le support. | [Field Effect](https://fieldeffect.com/blog/fake-zendesk-okta-pages-to-bypass-mfa) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Cyber Job Dating 2026 | Article promotionnel / RH sans contenu technique cyber. | [Campus Cyber](https://campuscyber.fr/cyber-job-dating-2026/) |
| RFC 1178 (1990): Choosing a Name | Contenu historique sans pertinence pour la menace actuelle. | [Social Media](https://infosec.exchange/@676e696f70/116382894635437907) |
| The TTP Ep. 22: The Collapse of the Patch Window | Doublon thématique avec l'article de Qualys/Qualys. | [Talos](https://blog.talosintelligence.com/video-the-ttp-ep-22-the-collapse-of-the-patch-window/) |
| Video live announcement Glasswing | Simple annonce de stream sur les réseaux sociaux. | [Social Media](https://infosec.exchange/@0ddj0bb/116383224584590245) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="supply-chain-attack-at-cpuid-pushes-malware-with-cpu-z-hwmonitor"></div>

## CPUID hacked to deliver malware via CPU-Z, HWMonitor downloads
Le site officiel de CPUID a été victime d'une attaque de la "supply chain" via le compromis d'une API secondaire. Pendant environ six heures, les liens de téléchargement des outils populaires CPU-Z et HWMonitor ont été détournés vers des exécutables malveillants hébergés sur Cloudflare R2. Le malware distribué est une version trojanisée de l'outil HWiNFO, emballée dans un installeur russe. Selon les chercheurs, ce loader est sophistiqué, fonctionnant presque entièrement en mémoire pour échapper aux EDR. L'attaquant utiliserait des techniques de proxying des fonctionnalités NTDLL via un assemblage .NET. Ce groupe semble être le même que celui ayant ciblé les utilisateurs de FileZilla le mois dernier. Les fichiers originaux signés par CPUID n'ont pas été compromis. Les détections antivirus identifient les échantillons comme étant des chevaux de Troie de type Tedy ou Artemis. CPUID a corrigé la faille et les téléchargements sont à présent sains.

**Analyse de l'impact** : Impact élevé pour les utilisateurs de diagnostic matériel, avec un risque massif d'infection de machines d'administration et de serveurs. L'évasion des EDR via l'exécution en mémoire augmente la dangerosité.

**Recommandations** : Vérifier les hachages des fichiers CPU-Z/HWMonitor téléchargés entre le 9 et le 10 avril 2026. Rechercher la présence de fichiers suspects dans `C:\Users\Public`. Surveiller les processus MSBuild.exe ou PowerShell.exe effectuant des appels réseau inhabituels.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (lié aux attaques FileZilla) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise * T1027.002: Software Packing * T1055: Process Injection |
| Observables & Indicateurs de compromission | ```* a8ba9ba93b4509a86e3d7dd40fd0652c2743e32277760c5f7942b788b74c5285 * 53c3e0f8627917e8972a627b9e68adf9c21966428a85cb1c28f47cb21db3c12b * HWiNFO_Monitor_Setup.zip``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/supply-chain-attack-at-cpuid-pushes-malware-with-cpu-z-hwmonitor/)
<br>
<br>

<div id="nearly-4000-us-industrial-devices-exposed-to-iranian-cyberattacks"></div>

## Nearly 4,000 US industrial devices exposed to Iranian cyberattacks
Des groupes de hackers liés à l'État iranien ciblent activement les automates programmables industriels (PLC) de marque Rockwell Automation/Allen-Bradley. Environ 4 000 de ces dispositifs sont actuellement exposés directement sur Internet aux États-Unis. Ces attaques, identifiées par le FBI, visent à extraire les fichiers de projet et à manipuler les données sur les écrans HMI/SCADA. Les campagnes ont commencé en mars 2026 en réponse aux hostilités régionales au Moyen-Orient. Censys rapporte que 74,6 % de l'exposition mondiale se situe aux États-Unis, souvent via des modems cellulaires. Les attaquants utilisent des ports OT spécifiques (44818, 2222, 502) pour pénétrer les réseaux. Ces incidents rappellent les vagues d'attaques des CyberAv3ngers contre les systèmes Unitronics l'année dernière. L'impact inclut des interruptions opérationnelles et des pertes financières significatives pour les secteurs de l'eau et de l'énergie.

**Analyse de l'impact** : Menace critique sur la sécurité physique et la continuité des services essentiels (eau, électricité).

**Recommandations** : Déconnecter immédiatement les PLC de l'Internet public. Utiliser des VPN avec MFA pour tout accès distant. Filtrer les adresses IP étrangères sur les pare-feu OT. Scanner les journaux pour toute activité sur le port 44818.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | APT liés à l'Iran (CyberAv3ngers, Handala) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0815: Asset Identification * T0831: Data Manipulation * T0883: Control Device Periphery |
| Observables & Indicateurs de compromission | ```* Trafic entrant sur ports 44818, 2222, 102, 502 * Connexions depuis des hébergeurs étrangers vers l'OT``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/nearly-4-000-us-industrial-devices-exposed-to-iranian-cyberattacks/)
<br>
<br>

<div id="analysis-of-one-billion-cisa-kev-remediation-records"></div>

## Analysis of one billion CISA KEV remediation records exposes limits of human-scale security
Une étude de Qualys portant sur un milliard de rapports de remédiation montre que le modèle actuel de défense cyber atteint un "plafond humain". Le temps moyen d'exploitation (Time-to-Exploit) est désormais de moins sept jours, signifiant que l'exploitation précède souvent le correctif. 88 % des vulnérabilités critiques sont remédiées plus lentement qu'elles ne sont exploitées par les adversaires. Le volume de vulnérabilités a augmenté de 6,5 fois depuis 2022, rendant la gestion manuelle impossible. L'IA accélère encore ce décalage en permettant aux attaquants de découvrir et d'armer des failles instantanément. Le concept de "Risk Mass" (masse de risque) est proposé pour mesurer l'exposition réelle cumulée plutôt que le simple nombre de CVE. Les systèmes d'infrastructure (endpoints exclus) affichent des délais de remédiation médians dépassant 230 jours. La transition vers des centres d'opérations de risque (ROC) autonomes est jugée nécessaire.

**Analyse de l'impact** : Dégradation structurelle de la posture de sécurité globale. Les entreprises perdent la "course à l'armement" temporelle contre les attaquants automatisés.

**Recommandations** : Prioriser la remédiation basée sur l'exploitabilité réelle (CISA KEV) plutôt que le score CVSS seul. Automatiser les workflows de patch pour les actifs critiques. Implémenter des contrôles compensatoires (IPS/WAF) dès l'annonce d'une faille.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (Étude statistique) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application * T1203: Exploitation for Client Execution |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/analysis-of-one-billion-cisa-kev-remediation-records-exposes-limits-of-human-scale-security/)
<br>
<br>

<div id="microsoft-canadian-employees-targeted-in-payroll-pirate-attacks"></div>

## Microsoft: Canadian employees targeted in payroll pirate attacks
L'acteur Storm-2755 mène des attaques sophistiquées de "piratage de paie" ciblant des employés au Canada. L'attaquant utilise des techniques d'Adversary-in-the-Middle (AiTM) pour voler des tokens de session et contourner la MFA. Les victimes sont attirées via de l'empoisonnement SEO vers de fausses pages de connexion Microsoft 365. Une fois l'accès obtenu, Storm-2755 crée des règles de boîte de réception pour cacher les emails de la RH. L'objectif est de modifier les informations de dépôt bancaire directement dans les plateformes comme Workday. Si l'accès logiciel échoue, l'acteur utilise l'ingénierie sociale pour tromper le personnel RH. Microsoft note que ces jetons volés permettent une réauthentification sans demande de credentials. Cette campagne s'inscrit dans une tendance de fraude BEC (Business Email Compromise) à haut rendement.

**Analyse de l'impact** : Impact financier direct pour les employés et risques de fraude interne pour les entreprises. Les méthodes MFA traditionnelles ne sont plus suffisantes.

**Recommandations** : Implémenter une MFA résistante au phishing (FIDO2/Passkeys). Bloquer les protocoles d'authentification hérités. Auditer régulièrement les règles de redirection d'emails suspectes.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Storm-2755 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link * T1557: Adversary-in-the-Middle * T1114.003: Email Forwarding Rule |
| Observables & Indicateurs de compromission | ```* bluegraintours[.]com * Domaines usurpant Microsoft 365``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-canadian-employees-targeted-in-payroll-pirate-attacks/)
<br>
<br>

<div id="uat-10362-linked-to-lucidrook-attacks-targeting-taiwan"></div>

## UAT-10362 linked to LucidRook attacks targeting Taiwan-based institutions
Cisco Talos a identifié une nouvelle campagne de phishing ciblant des ONG et des universités à Taïwan. L'acteur, UAT-10362, déploie le malware LucidRook, un stager sophistiqué écrit en Lua et Rust. Les vecteurs d'infection utilisent des archives RAR protégées par mot de passe pour échapper aux analyses automatiques. Le malware utilise le "DLL sideloading" via un exécutable DISM légitime pour maintenir la discrétion. LucidRook collecte des données système, les chiffre avec RSA et les exfiltre via FTP en utilisant des serveurs publics abusés. Une variante nommée LucidKnight est également utilisée pour la reconnaissance via SMTP Gmail. Le malware vérifie la langue du système (Chinois traditionnel) avant de s'exécuter pour éviter les environnements de test. L'ingénierie logicielle témoigne d'un investissement significatif pour la furtivité.

**Analyse de l'impact** : Risque d'espionnage et de vol de données pour les entités académiques et civiles dans une zone de haute tension géopolitique.

**Recommandations** : Surveiller l'utilisation anormale de l'outil DISM.exe. Bloquer les connexions FTP sortantes vers des hôtes inconnus. Rechercher des requêtes DNS vers `dnslog.ink`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAT-10362 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1574.002: DLL Side-Loading * T1059.006: Python/Lua Bytecode * T1614: System Location Discovery |
| Observables & Indicateurs de compromission | ```* dnslog[.]ink * archive1.zip * archive.zip``` |

### Source (url) du ou des articles
* [Security Affairs](https://securityaffairs.com/190598/security/uat-10362-linked-to-lucidrook-attacks-targeting-taiwan-based-institutions.html)
<br>
<br>

<div id="unc6783-uses-fake-zendesk-and-okta-pages-to-bypass-mfa"></div>

## UNC6783 Uses Fake Zendesk and Okta Pages to Bypass MFA and Steal Data
Le groupe UNC6783 cible les prestataires d'externalisation de processus métier (BPO) pour voler des données d'entreprise. L'attaque commence par un chat en direct où les employés sont dirigés vers de fausses pages Zendesk ou Okta. Ces domaines utilisent des motifs prévisibles comme `<org>.zendesk-support<##>.com`. Le phishing kit utilisé est capable de voler le contenu du presse-papier pour intercepter les codes MFA. Une fois compromis, l'attaquant enregistre ses propres dispositifs pour maintenir un accès persistant. Des tickets de support, des documents internes et des données d'employés sont exfiltrés à des fins d'extorsion. Le groupe serait lié au persona cybercriminel "Mr. Raccoon". Les demandes de rançon sont envoyées via des comptes Proton Mail.

**Analyse de l'impact** : Risque élevé de fuite de données confidentielles et d'extorsion. Les processus de support deviennent un vecteur d'intrusion majeur.

**Recommandations** : Interdire le partage de liens d'authentification via les outils de chat. Utiliser des clés de sécurité matérielles (FIDO2). Surveiller l'enregistrement de nouveaux dispositifs MFA.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6783 (alias Raccoon) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.003: Spearphishing Service * T1098.005: Device Registration * T1213: Data from Information Repositories |
| Observables & Indicateurs de compromission | ```* <org>[.]zendesk-support<##>[.]com * Emails provenant de Proton Mail pour l'extorsion``` |

### Source (url) du ou des articles
* [Field Effect](https://fieldeffect.com/blog/fake-zendesk-okta-pages-to-bypass-mfa)
<br>
<br>

<div id="potential-adobe-reader-zero-day-reported"></div>

## Potential Adobe Reader Zero-Day Reported
Un chercheur en sécurité a signalé une possible vulnérabilité zero-day dans Adobe Acrobat Reader. La faille permettrait d'accéder à des API JavaScript privilégiées (util.readFileIntoStream, RSS.addFeed) pour lire des fichiers locaux arbitraires. L'exploitation reposerait sur du JavaScript fortement obfusqué intégré dans des PDF. Des preuves suggèrent que cette activité pourrait dater de novembre 2025. Des leurres en langue russe liés au secteur de l'énergie (pétrole et gaz) ont été observés. Adobe n'a pas encore confirmé officiellement la vulnérabilité ni publié de correctif. Les noms de fichiers associés incluent `yummy_adobe_exploit_uwu.pdf` et `Invoice540.pdf`.

**Analyse de l'impact** : Risque d'exfiltration de données et d'exécution de code à distance si la vulnérabilité est confirmée.

**Recommandations** : Désactiver l'exécution du JavaScript dans Adobe Reader. Utiliser des visionneuses PDF natives (navigateurs) pour les fichiers provenant de sources externes. Surveiller les accès fichiers inhabituels par le processus `AcroRd32.exe`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (indices de ciblage russe) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution * T1027: Obfuscated Files or Information |
| Observables & Indicateurs de compromission | ```* yummy_adobe_exploit_uwu.pdf * Invoice540.pdf``` |

### Source (url) du ou des articles
* [Field Effect](https://fieldeffect.com/blog/researcher-reports-potential-adobe-reader-zero-day)