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
  * [Campagne de supply chain de teampcp](#campagne-de-supply-chain-de-teampcp)
  * [Framework dexploit coruna](#framework-dexploit-coruna)
  * [Analyse des clusters de menaces en asie du sud-est](#analyse-des-clusters-de-menaces-en-asie-du-sud-est)
  * [Evolution de scarlet goldfinch et du clickfix](#evolution-de-scarlet-goldfinch-et-du-clickfix)
  * [Nouveau skimmer webrtc contournant les defenses](#nouveau-skimmer-webrtc-contournant-les-defenses)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
En mars 2026, le paysage cyber est marqué par une sophistication sans précédent des attaques sur la chaîne d'approvisionnement, illustrée par la campagne massive du groupe TeamPCP ciblant les outils de sécurité (Trivy, Checkmarx). L'écosystème de l'intelligence artificielle est devenu une cible prioritaire, avec des compromissions directes de passerelles comme LiteLLM et des vulnérabilités critiques exploitées dans Langflow. Parallèlement, le framework d'espionnage Coruna démontre une évolution inquiétante de la menace mobile, recyclant les capacités d'Operation Triangulation pour cibler les derniers processeurs Apple. Les tensions au Moyen-Orient provoquent une escalade de cyber-activisme et de logiciels destructeurs (wipers) iraniens, tandis que l'Asie du Sud-Est subit une pression constante de clusters d'espionnage chinois coordonnés. La technique du "ClickFix" ou "paste and run" s'impose désormais comme un vecteur d'accès initial dominant, surpassant les méthodes traditionnelles par sa simplicité et son efficacité. Les autorités tentent de riposter par des actions de démantèlement (LeakBase) et un renforcement réglementaire (DSA), mais la vélocité des attaquants reste un défi majeur. Enfin, la dépendance accrue aux agents de codage IA introduit de nouvelles faiblesses structurelles dans les développements logiciels récents.
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
| APT Iran | Gouvernement, Défense | Sabotage d'infrastructures, fuite de données | [Josh J](https://sploited.blog/2026/03/26/weekly-threat-landscape-thursday-roundup-1/) |
| DragonForce | Divers (Industrie, Santé, PME) | Ransomware, double extorsion | [Ransomlook](https://www.ransomlook.io//group/dragonforce) |
| Handala Hack | Défense (Lockheed Martin) | Menaces par email, exfiltration de données | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/) |
| LAPSUS$ | Technologie, Défense | Collaboration avec TeamPCP, ingénierie sociale | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-supply-chain-campaign) |
| Nightspire | Santé, Immobilier, Services | Ransomware, publication de victimes | [Ransomlook](https://www.ransomlook.io//group/nightspire) |
| Scarlet Goldfinch | Divers | Technique "ClickFix" (paste and run), JS malveillant | [Red Canary](https://redcanary.com/blog/threat-intelligence/scarlet-goldfinch-clickfix/) |
| Shinyhunters | Forums cyber, Snowflake, Salesforce | Extorsion, menaces de fuites massives | [Ransomlook](https://www.ransomlook.io//group/shinyhunters) |
| Stately Taurus | Gouvernements (Asie du Sud-Est) | Malware USBFect (Worm), PUBLOAD backdoor | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/) |
| TeamPCP | Chaîne d'approvisionnement logicielle | Empoisonnement de packages PyPI/npm, automation | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-supply-chain-campaign) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense | Guerre Israël-Iran | Escalade des cyberattaques iraniens suite aux opérations Epic Fury et Roaring Lion. | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/) |
| Économie | Sécurité Économique | La France lance une mission parlementaire pour protéger ses actifs stratégiques. | [Portail de l'IE](https://www.portail-ie.fr/univers/2026/mission-parlementaire-securite-economique/) |
| Finance | Sanctions UK | Le Royaume-Uni sanctionne la place de marché Xinbi liée aux arnaques en Asie. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/uk-sanctions-xinbi-marketplace-linked-to-asian-scam-centers/) |
| Gouvernement | Rivalité USA-Chine | Analyse des vulnérabilités créées par la neutralité face à la stratégie chinoise. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/great-power-delusion-western-governments-and-china) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Breach of the Digital Services Act | Commission Européenne | 26/03/2026 | Union Européenne | DSA (Digital Services Act) | Violation préliminaire pour défaut de protection des mineurs (Pornhub, Snapchat, etc.). | [EU Commission](https://digital-strategy.ec.europa.eu/en/news/commission-preliminarily-finds-pornhub-stripchat-xnxx-and-xvideos-breach-digital-services-act) |
| FCC proposes forcing call center onshoring | The Register | 26/03/2026 | États-Unis | FCC Draft Rules | Proposition visant à rapatrier les centres d'appels pour des raisons de sécurité et de confidentialité. | [The Register](https://www.theregister.com/2026/03/26/ai_companies_lick_their_chops/) |
| LastPass Canadian Class Action | Edwin G. | 26/03/2026 | Canada | Recours collectif | Règlement approuvé pour l'indemnisation des victimes de la fuite de données de 2022. | [Mastodon](https://mstdn.moimeme.ca/@EdwinG/116298351054910131) |
| Lobbying et trafic d’influence | Lucile Petit | 26/03/2026 | France | Loi Sapin II | Analyse de la frontière pénale entre lobbying licite et trafic d'influence réprimé. | [Portail de l'IE](https://www.portail-ie.fr/univers/droit-et-intelligence-juridique/2026/lobbying-et-trafic-dinfluence-ou-se-situe-la-frontiere-penale/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Divertissement | Scuf Gaming | 129k comptes exposés (emails, mots de passe hachés, IPs). | [HIBP](https://haveibeenpwned.com/Breach/ScufGaming) |
| Sport | AFC Ajax | Hacker néerlandais ayant accédé aux données de supporters et modifié des interdictions de stade. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ajax-football-club-hack-exposed-fan-data-enabled-ticket-hijack/) |
| Technologie | Sound Radix | 293k noms et adresses emails compromis. | [HIBP](https://haveibeenpwned.com/Breach/SoundRadix) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-22738 | 9.8 | N/A | FALSE | Spring AI (SimpleVectorStore) | SpEL Injection | Non mentionnées | Injection d'expression permettant l'exécution de code arbitraire via des filtres de vecteurs. | [SecurityOnline](https://securityonline.info/spring-ai-security-vulnerabilities-rce-ssrf-spel-injection-patch/) |
| CVE-2026-33634 | 9.4 | N/A | TRUE | Aqua Security Trivy | Supply Chain / PAT Theft | T1190: Exploit Public-Facing Application | Vol de jetons d'accès (PAT) via exploitation d'un workflow GitHub mal configuré. | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-supply-chain-campaign) |
| CVE-2026-33017 | 9.3 | N/A | TRUE | Langflow | Code Injection | T1059: Command and Scripting Interpreter | Exécution de code Python arbitraire sans authentification via un endpoint public non sécurisé. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-new-langflow-flaw-actively-exploited-to-hijack-ai-workflows/) |
| CVE-2026-4903 | 9.0 | N/A | FALSE | Tenda AC5 | Stack-based Overflow | Non mentionnées | Corruption mémoire dans la fonction formQuickIndex via l'argument PPPOEPassword. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4903) |
| CVE-2026-33945 | 9.9 | N/A | FALSE | Incus | Path Traversal / Arbitrary Write | T1222: File and Directory Permissions Modification | Écriture de fichiers arbitraires en tant que root via l'option systemd-creds. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33945) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| TeamPCP Supply Chain Campaign | Analyse exhaustive d'une attaque en cascade majeure sur la supply chain. | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-supply-chain-campaign) |
| Coruna: the framework used in Operation Triangulation | Lien technique direct entre une menace étatique iOS connue et une nouvelle variante. | [Securelist](https://securelist.com/coruna-framework-updated-operation-triangulation-exploit/119228/) |
| Analysis of Threat Clusters Targeting a Southeast Asian Government | Détails sur le ciblage multi-acteurs (Stately Taurus) d'une entité souveraine. | [Unit 42](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/) |
| Scarlet Goldfinch’s year in ClickFix | Étude de l'évolution des techniques d'accès initial par copier-coller malveillant. | [Red Canary](https://redcanary.com/blog/threat-intelligence/scarlet-goldfinch-clickfix/) |
| WebRTC skimmer bypassing traditional defenses | Innovation technique dans l'exfiltration de données via WebRTC. | [SecurityAffairs](https://securityaffairs.com/190002/malware/researchers-uncover-webrtc-skimmer-bypassing-traditional-defenses.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| OpenSSF Newsletter – March 2026 | Contenu principalement promotionnel et organisationnel. | [OpenSSF](https://opensf.org/newsletter/2026/03/26/openssf-newsletter-march-2026/) |
| WhatsApp rolls out more AI features | Actualité produit/fonctionnalités sans composant cyber critique. | [BleepingComputer](https://www.bleepingcomputer.com/news/software/whatsapp-rolls-out-more-ai-features-ios-multi-account-support/) |
| Field Effect MDRICE Marketplace | Annonce de partenariat commercial simple. | [Field Effect](https://fieldeffect.com/blog/field-effect-partner-network-mortgage-lenders) |
| Inside a Modern Fraud Attack | Article pédagogique généraliste sans incident spécifique récent. | [IPQS](https://www.bleepingcomputer.com/news/security/inside-a-modern-fraud-attack-from-bot-signups-to-account-takeovers/) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES
<div id="campagne-de-supply-chain-de-teampcp"></div>

## Campagne de supply chain de TeamPCP
Le groupe TeamPCP a mené en mars 2026 une campagne d'attaque sur la chaîne d'approvisionnement logicielle d'une sophistication rare. Tout a commencé par l'exploitation d'une mauvaise configuration de workflow GitHub (pull_request_target) dans le projet Trivy d'Aqua Security. Les attaquants ont réussi à voler des jetons d'accès personnels (PAT) avec des privilèges étendus sur l'organisation. Ces jetons ont été utilisés pour empoisonner des images Docker et des actions GitHub, propageant le malware à des projets dépendants comme LiteLLM. Plus de 64 packages npm ont été infectés en moins d'une minute via un ver nommé CanisterWorm. La campagne visait principalement le vol de secrets (clés AWS, Kubernetes, portefeuilles crypto) sur les serveurs CI/CD. Une variante destructrice (wiper) a également été observée, ciblant spécifiquement des infrastructures en Iran. L'attaque souligne la dangerosité des jetons à longue durée de vie et des tags de version mutables.

**Analyse de l'impact** : Impact massif sur l'écosystème open-source et les pipelines de déploiement cloud. La confiance dans les outils de scan de sécurité a été directement entamée, les attaquants ayant utilisé ces outils comme chevaux de Troie.

**Recommandations** : 
* Utiliser des jetons OIDC de courte durée plutôt que des PAT statiques.
* Fixer les actions GitHub avec des SHAs de commit complets et non des tags (v1.0).
* Auditer les workflows pour interdire l'usage de `pull_request_target` avec des secrets.
* Surveiller toute création inhabituelle de dépôts (ex: pattern `tpcp-docs`).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (DeadCatx3, PCPcat, ShellForce) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1552.001: Credentials In Files <br/> * T1537: Transfer Data to Cloud Account |
| Observables & Indicateurs de compromission | ```* scan.aquasecurtiy[.]org (C2) * models.litellm.cloud (C2) * ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg (Hash litellm_init.pth)``` |

### Source (url) du ou des articles
* https://opensourcemalware.com/blog/teampcp-supply-chain-campaign
* https://securelist.com/litellm-supply-chain-attack/119257/
* https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-backdoored-to-steal-credentials-auth-tokens/

<br>
<br>
<div id="framework-dexploit-coruna"></div>

## Framework d'exploit Coruna
Coruna est un kit d'exploitation iOS hautement sophistiqué, identifié comme le successeur direct de l'infrastructure utilisée dans l'opération d'espionnage "Triangulation". Il contient cinq chaînes d'exploitation complètes totalisant 23 vulnérabilités, dont CVE-2023-32434 et CVE-2023-38606. Contrairement à une simple collection d'exploits publics, Coruna est un framework unifié et maintenu, capable de cibler les architectures ARM64 et ARM64E. Il a été mis à jour pour compromettre les puces Apple les plus récentes (A17, M3) et les versions d'iOS allant jusqu'à la 17.2. L'attaque débute souvent via Safari avec un "stager" qui identifie le matériel avant de déployer un implant espion. Bien qu'initialement conçu pour l'espionnage d'État, le kit est désormais utilisé par des acteurs cybercriminels à des fins financières, notamment pour le vol de cryptomonnaies. Kaspersky souligne que la réutilisation de code prouve une évolution continue du framework original.

**Analyse de l'impact** : Risque critique pour les utilisateurs d'iPhone n'ayant pas effectué les mises à jour de sécurité récentes. La mise à disposition de tels outils sur le marché "secondaire" augmente drastiquement la menace pour les cibles de haut profil.

**Recommandations** : 
* Maintenir les appareils iOS à la version la plus récente disponible.
* Activer le "Lockdown Mode" pour les utilisateurs à haut risque (journalistes, officiels).
* Surveiller les communications réseaux suspectes provenant de terminaux mobiles vers des adresses IP non identifiées.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs de Coruna (liens avec Operation Triangulation) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.001: Malicious Link <br/> * T1406: Exploitation for Privilege Escalation <br/> * T1513: Screen Capture (Mobile) |
| Observables & Indicateurs de compromission | ```* CVE-2023-32434 * CVE-2023-38606 * Utilisation du chiffrement ChaCha20 pour les payloads``` |

### Source (url) du ou des articles
* https://securelist.com/coruna-framework-updated-operation-triangulation-exploit/119228/
* https://www.bleepingcomputer.com/news/security/coruna-ios-exploit-framework-linked-to-triangulation-attacks/

<br>
<br>
<div id="analyse-des-clusters-de-menaces-en-asie-du-sud-est"></div>

## Analyse des clusters de menaces en Asie du Sud-Est
Unit 42 a identifié trois clusters d'activité cyberespionnage distincts ciblant simultanément une organisation gouvernementale en Asie du Sud-Est. Le premier, Stately Taurus, utilise le malware USBFect pour se propager latéralement via des supports amovibles et déployer la backdoor PUBLOAD. Le second cluster, CL-STA-1048, déploie une panoplie d'outils incluant les RATs Masol et Gorem, ainsi que le stealer TrackBak, pour établir une persistance robuste. Le troisième, CL-STA-1049, privilégie la discrétion avec le chargeur "Hypnosis" pour livrer le RAT FluffyGh0st. Les analyses montrent des chevauchements significatifs avec d'autres campagnes chinoises connues telles que Crimson Palace et Unfading Sea Haze. Cette convergence suggère une coordination stratégique ou un partage de ressources entre plusieurs unités de renseignement. L'objectif principal semble être l'exfiltration continue de données sensibles sur le long terme.

**Analyse de l'impact** : Menace persistante avancée (APT) sur la souveraineté des données nationales. L'utilisation de multiples vecteurs (USB, sideloading de DLL) rend la détection complexe pour les infrastructures traditionnelles.

**Recommandations** : 
* Restreindre strictement l'usage des ports USB sur les postes sensibles.
* Implémenter une solution EDR/XDR capable de détecter le DLL side-loading.
* Monitorer les protocoles non standards (gRPC) utilisés par Gorem RAT pour le C2.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Stately Taurus, CL-STA-1048, CL-STA-1049 (liens Chine) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1091: Replication Through Removable Media <br/> * T1574.002: DLL Side-Loading <br/> * T1071.004: DNS (C2) |
| Observables & Indicateurs de compromission | ```* webmail.rpcthai[.]com * laichingte[.]net * 4b29b74798a4e6538f2ba245c57be82953383dc91fe0a91b984b903d12043e92 (EVENT.dll)``` |

### Source (url) du ou des articles
* https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/

<br>
<br>
<div id="evolution-de-scarlet-goldfinch-et-du-clickfix"></div>

## Evolution de Scarlet Goldfinch et du ClickFix
L'acteur Scarlet Goldfinch a pivoté de ses tactiques de faux updates de navigateurs vers une méthode dite "ClickFix" ou "paste and run". Cette technique consiste à piéger l'utilisateur via une fausse alerte de sécurité (ex: CAPTCHA ou erreur de certificat) l'invitant à copier et coller une commande PowerShell ou CMD dans son terminal pour "réparer" le problème. En 2026, l'acteur a affiné ses méthodes pour contourner les détections EDR, en utilisant notamment l'expansion retardée des variables d'environnement (`cmd.exe /v:on`) pour masquer ses commandes curl. Le payload final est souvent NetSupport Manager ou Remcos RAT, utilisés pour le contrôle à distance. Scarlet Goldfinch se distingue par sa capacité à modifier ses commandes en quelques jours dès que des opportunités de détection sont publiées. L'attaque repose entièrement sur l'ingénierie sociale plutôt que sur des exploits logiciels complexes.

**Analyse de l'impact** : Risque élevé d'accès initial sur les postes de travail d'entreprise. Cette méthode contourne les passerelles de messagerie car l'interaction se fait directement sur un site web compromis.

**Recommandations** : 
* Sensibiliser les utilisateurs à ne jamais copier-coller de commandes système provenant de sites web.
* Bloquer ou monitorer l'exécution de `mshta.exe` et l'usage de `curl` par des processus utilisateurs.
* Utiliser des politiques de restriction logicielle pour limiter l'exécution de scripts PowerShell non signés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Scarlet Goldfinch (SmartApeSG, ZPHP) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.004: Malicious Copy and Paste <br/> * T1059.001: PowerShell <br/> * T1218.005: Mshta |
| Observables & Indicateurs de compromission | ```* Patterns de staging dans AppData\Local * Usage excessif du caractère d'échappement ^ dans les lignes de commande``` |

### Source (url) du ou des articles
* https://redcanary.com/blog/threat-intelligence/scarlet-goldfinch-clickfix/

<br>
<br>
<div id="nouveau-skimmer-webrtc-contournant-les-defenses"></div>

## Nouveau skimmer WebRTC contournant les défenses
Des chercheurs de Sansec ont découvert une nouvelle forme de skimmer de paiement utilisant les canaux de données WebRTC pour exfiltrer les informations bancaires. Contrairement aux skimmers traditionnels qui utilisent des requêtes HTTP ou des balises d'images détectables par les politiques de sécurité de contenu (CSP), ce malware crée une connexion peer-to-peer chiffrée. En exploitant la vulnérabilité PolyShell dans Magento/Adobe Commerce, les attaquants injectent un script qui communique via UDP port 3479. Le trafic WebRTC est rarement inspecté par les outils de sécurité réseau standard car il utilise le protocole DTLS chiffré. Le skimmer vole également les nonces CSP valides pour s'injecter silencieusement dans la page. Cette technique permet de voler des données de carte de crédit sans laisser de traces visibles dans les logs HTTP classiques.

**Analyse de l'impact** : Menace sérieuse pour le e-commerce. La méthode d'exfiltration furtive rend les solutions de défense front-end (WAF, CSP) inefficaces sans une configuration spécifique WebRTC.

**Recommandations** : 
* Mettre à jour Magento/Adobe Commerce pour corriger la faille PolyShell.
* Restreindre les connexions WebRTC via les directives CSP `connect-src` si possible.
* Monitorer les flux UDP inhabituels sortants du navigateur vers des IPs inconnues.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1557: Adversary-in-the-Middle <br/> * T1048.003: Exfiltration Over Uncommonly Used Port <br/> * T1592: Steal Web Session Cookie |
| Observables & Indicateurs de compromission | ```* 202.181.177[.]177 (IP de destination) * Port UDP 3479``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190002/malware/researchers-uncover-webrtc-skimmer-bypassing-traditional-defenses.html