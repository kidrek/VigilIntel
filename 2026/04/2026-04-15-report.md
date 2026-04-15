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
  * [phantompulse-un-rat-distribue-via-des-plugins-obsidian](#phantompulse-un-rat-distribue-via-des-plugins-obsidian)
  * [stardrop-une-attaque-majeure-de-la-supply-chain-npm](#stardrop-une-attaque-majeure-de-la-supply-chain-npm)
  * [escalade-cyber-dans-le-conflit-us-israel-iran](#escalade-cyber-dans-le-conflit-us-israel-iran)
  * [analyse-du-patch-tuesday-record-davril-2026](#analyse-du-patch-tuesday-record-davril-2026)
  * [breche-chez-rockstar-games-lexfiltration-shinyhunters](#breche-chez-rockstar-games-lexfiltration-shinyhunters)
  * [campagne-de-malware-via-de-fausses-ia-claude](#campagne-de-malware-via-de-fausses-ia-claude)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace cyber en avril 2026 est marqué par une convergence sans précédent entre tensions géopolitiques extrêmes et industrialisation des attaques sur la chaîne d'approvisionnement. Le conflit opposant les États-Unis, Israël et l'Iran bascule dans une phase critique avec l'annonce d'un blocus naval, déclenchant des opérations de sabotage numérique massives par des groupes comme Handala et Z-PENTEST. Parallèlement, Microsoft enregistre un Patch Tuesday record avec plus de 240 vulnérabilités, soulignant une exploitation croissante de failles zero-day dans des infrastructures critiques (SharePoint, Windows TCP/IP). L'écosystème des outils de productivité (Obsidian) et de développement (NPM) est désormais directement ciblé pour l'accès initial, contournant les protections périmétriques traditionnelles. Les entreprises doivent faire face à une menace hybride où l'espionnage étatique et l'extorsion financière (ShinyHunters) utilisent les mêmes vecteurs d'accès via les services cloud et les identités non-humaines. La compromission massive de données chez Basic-Fit et McGraw-Hill confirme que les configurations cloud (Salesforce, Snowflake) demeurent le maillon faible de la défense. Une vigilance accrue sur la gestion des secrets et l'authentification forte est impérative pour les décideurs.
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
| Anubis | Santé (Hôpitaux) | Ransomware, vol de données (2TB), menace de destruction | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| APT29 | Gouvernemental, Entreprises | Phishing via fichiers de configuration RDP malveillants | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-adds-windows-protections-for-malicious-remote-desktop-files/) |
| Handala (Void Manticore) | Gouvernements, Infrastructures (Dubaï, Israël) | Wiper, attaques destructrices de données (6PB), exfiltration massive | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| MuddyWater (Seedworm) | Défense, Aérospatiale | Opération Olalampo, CastleRAT, C2 via blockchain | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| REF6598 (Opérateurs de PhantomPulse) | Finance, Crypto-monnaies | Social engineering (LinkedIn/Telegram), plugins Obsidian malveillants | [Elastic Security](https://www.elastic.co/security-labs/phantom-in-the-vault) |
| Scattered Spider (UNC3944) | SaaS, Retail, Aérien | Social engineering (Help desk), vol de logs d'infostealers, accès Okta/Snowflake | [Flare](https://flare.io/learn/resources/blog/identity-kill-chain-complete-history-identity-security) |
| ShinyHunters | Gaming, Édition, Cloud | Extorsion, exploitation de mauvaises configurations cloud (Salesforce, Snowflake) | [Security Affairs](https://securityaffairs.com/190796/data-breach/shinyhunters-claim-the-hack-of-rockstar-games-breach-and-started-leaking-data.html) |
| Z-PENTEST Alliance | Systèmes industriels (OT/ICS) | Accès aux automates (PLC), contrôle en temps réel (eau) | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernemental (Dubaï) | Conflit Moyen-Orient | Handala revendique la destruction de 6 pétaoctets de données gouvernementales en représailles à la posture régionale des Émirats. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Industriel (S. Corée) | Conflit Moyen-Orient | Le groupe Z-PENTEST prétend avoir pris le contrôle d'un système de traitement d'eau industriel en Corée du Sud. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Maritime / Énergie | Blocus Naval | Les États-Unis annoncent un blocus naval des ports iraniens ; l'Iran menace de cibler tous les ports du Golfe en réponse. | [Recorded Future](https://www.recordedfuture.com/research/iran-war-future-scenario-and-business-improvements) |
| Militaire (Défense) | Coopération France-Corée | Visite d'État d'Emmanuel Macron à Séoul pour renforcer le partenariat de sécurité (propulsion sous-marine, armement). | [IRIS](https://www.iris-france.org/macrons-state-visit-and-the-case-for-a-deeper-korea-france-security-partnership/) |
| National (Hongrie) | Élections | Défaite électorale de Viktor Orbán le 12 avril 2026, marquant un tournant pour les équilibres politiques de l'UE. | [IRIS](https://www.iris-france.org/ce-que-les-elections-hongroises-nous-apprennent-de-lunion-europeenne/) |
| Politique / Religion | Guerre en Ukraine | Analyse de l'instrumentalisation de l'Église orthodoxe par la Russie pour des opérations d'influence et d'interférence (FIMI). | [EUvsDisinfo](https://euvsdisinfo.eu/how-russia-weaponizes-the-church-in-ukraine/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| California’s cybersecurity audit rule is now in effect | IAPP | 14/04/2026 | États-Unis (Californie) | Audit Rule (CPPA) | Obligation pour certaines entreprises de réaliser un audit annuel de cybersécurité certifié. | [DataBreaches.net](https://databreaches.net/2026/04/14/californias-cybersecurity-audit-rule-is-now-in-effect-its-impact-for-class-litigation/) |
| GDPR and ePrivacy at risk | EDRi | 14/04/2026 | Union Européenne | RGPD / ePrivacy | Débats sur la "simplification" du RGPD et les risques de dérégulation sous pression politique et économique. | [EDRi](https://edri.org/our-work/privacycamp25-event-summary/) |
| Guidance for compliance with NIS2, DORA | Sysdig | 14/04/2026 | Union Européenne | NIS2 / DORA | Guide pratique pour la conformité aux nouvelles directives européennes de sécurité des réseaux et de résilience opérationnelle. | [Sysdig](https://webflow.sysdig.com/blog/cloud-security-and-compliance-nis2-dora) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Divertissement / Gaming | Rockstar Games | Leak de 8.1 Go (code source anti-cheat, données financières) via une brèche chez un tiers (Snowflake/Anodot). | [Security Affairs](https://securityaffairs.com/190796/data-breach/shinyhunters-claim-the-hack-of-rockstar-games-breach-and-started-leaking-data.html) |
| Éducation | McGraw-Hill | Exposition de données via une mauvaise configuration Salesforce, revendiquée par ShinyHunters (45M de records). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/mcgraw-hill-confirms-data-breach-following-extortion-threat/) |
| Finance (Crypto) | Kraken | Menace d'extorsion suite à un recrutement malveillant d'un employé de support (insider threat) ; 2 000 comptes affectés. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/crypto-exchange-kraken-extorted-by-hackers-after-insider-breach/) |
| Loisirs (Sport) | Basic-Fit | Accès non autorisé aux systèmes de visite ; vol de données (noms, RIB, dates de naissance) d'un million de membres. | [Security Affairs](https://securityaffairs.com/190815/data-breach/personal-data-of-1-million-gym-members-compromised-in-basic-fit-security-incident.html) |
| Santé | Signature Healthcare | Ransomware Anubis ; vol de 2 To de données patients et arrêt des systèmes informatiques depuis 8 jours. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées.
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-40175 | 9.9 | N/A | FALSE | Axios (<1.15.0) | CRLF Injection / Prototype Pollution | T1190: Exploit Public-Facing Application | Escalade vers RCE ou compromission cloud via accès aux métadonnées AWS. | [Field Effect](https://fieldeffect.com/blog/dependency-interactions-axios-network-layer-exposure-threat) |
| CVE-2026-33824 | 9.8 | N/A | FALSE | Windows IKE | Double Free | N/A | Exécution de code à distance via des paquets forgés (IKE version 2). | [Talos](https://blog.talosintelligence.com/microsoft-patch-tuesday-april-2026/) |
| CVE-2026-39399 | 9.6 | N/A | FALSE | NuGet Gallery | Path Traversal / Metadata Injection | T1195: Supply Chain Compromise | Injection de métadonnées malveillantes via nuspec permettant une RCE. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-39399) |
| CVE-2025-0520 | 9.4 | N/A | TRUE | ShowDoc | Unrestricted File Upload | T1190: Exploit Public-Facing Application | Permet l'exécution de code PHP arbitraire sur les serveurs non patchés. | [Security Affairs](https://securityaffairs.com/190790/hacking/attackers-target-unpatched-showdoc-servers-via-cve-2025-0520.html) |
| CVE-2026-35033 | 9.3 | N/A | FALSE | Jellyfin (<10.11.7) | Argument Injection | N/A | Lecture de fichiers arbitraires (ex: /etc/shadow) via injection ffmpeg. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-35033) |
| CVE-2026-34457 | 9.1 | N/A | FALSE | OAuth2 Proxy | Auth Bypass | T1550: Use Alternate Authentication Material | Contournement d'authentification via manipulation du User-Agent de health check. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-34457) |
| CVE-2026-34621 | 8.6 | N/A | TRUE | Adobe Acrobat Reader | Prototype Pollution | T1203: Exploitation for Client Execution | Activement exploitée pour exécuter du code à distance. | [CISA](https://securityaffairs.com/190775/security/u-s-cisa-adds-adobe-fortinet-microsoft-windows-microsoft-exchange-server-and-microsoft-windows-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-32201 | 6.5 | N/A | TRUE | MS SharePoint | Spoofing | T1204.002: Malicious File | Activement exploitée pour tromper les utilisateurs via du contenu falsifié. | [Microsoft](https://isc.sans.edu/diary/32898) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT | Nouvelle technique d'accès initial via plugins d'outils de productivité. | [Elastic Security](https://www.elastic.co/security-labs/phantom-in-the-vault) |
| Stardrop Supply Chain Attack | Campagne massive (200+ packages) ciblant les secteurs IA et Finance. | [OSM](https://opensourcemalware.com/blog/stardrop-attack) |
| Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Conflict | Rapport détaillé sur la cyberguerre destructrice liée à l'actualité chaude. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Microsoft Patch Tuesday April 2026 | Analyse d'un volume record de vulnérabilités et de failles zero-day. | [ISC SANS](https://isc.sans.edu/diary/32898) |
| ShinyHunters claim the hack of Rockstar Games | Incident majeur d'exfiltration touchant une cible à haute visibilité. | [Security Affairs](https://securityaffairs.com/190796/data-breach/shinyhunters-claim-the-hack-of-rockstar-games-breach-and-started-leaking-data.html) |
| Fake Claude AI installer abuses DLL sideloading | Exploitation de la tendance IA pour distribuer PlugX RAT. | [Security Affairs](https://securityaffairs.com/190754/malware/fake-claude-ai-installer-abuses-dll-sideloading-to-deploy-plugx.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| The Identity Kill Chain: A Complete History | Contenu essentiellement historique et éducatif, manque d'actualité immédiate. | [Flare](https://flare.io/learn/resources/blog/identity-kill-chain-complete-history-identity-security) |
| Use response actions to update Zscaler policies | Communiqué de presse orienté produit/marketing. | [Red Canary](https://redcanary.com/blog/product-updates/zia-response-actions/) |
| Use in-use vulnerability prioritization | Article promotionnel pour une solution spécifique (Sysdig). | [Sysdig](https://webflow.sysdig.com/blog/smarter-vulnerability-management-with-in-use-prioritization) |
| FBI Atlanta Takedown (Reddit) | Lien bloqué ou accès restreint au moment de l'analyse. | [Reddit](https://www.reddit.com/r/blueteamsec/comments/1slmfmb/fbi_atlanta_indonesian_authorities_take_down/) |
| Netgear firmware issues (Mastodon) | Information de niveau domestique/individuel, peu pertinente pour l'entreprise. | [Mastodon](https://federate.social/@jik/116405681745569037) |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="phantompulse-un-rat-distribue-via-des-plugins-obsidian"></div>

## Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT
Cette campagne, suivie sous le nom de REF6598, utilise l'ingénierie sociale sur LinkedIn et Telegram pour cibler les secteurs de la finance et des crypto-monnaies. Les attaquants invitent les victimes à accéder à un coffre (vault) partagé sur l'application de prise de notes Obsidian. Une fois le coffre ouvert, ils poussent les victimes à activer la synchronisation des plugins communautaires. Des plugins légitimes tels que "Shell Commands" et "Hider" sont détournés pour exécuter silencieusement du code PowerShell ou AppleScript. Sur Windows, le chargeur "PhantomPull" déchiffre en mémoire le RAT "PhantomPulse". Ce dernier utilise des techniques avancées d'injection et, de manière innovante, résout l'adresse de son serveur C2 via des transactions sur la blockchain Ethereum. Les chaînes de blocs Ethereum L1, Base L2 et Optimism L2 sont utilisées comme dead-drop pour l'infrastructure adverse. Cette méthode rend l'infrastructure très résiliente face au blocage de domaines classiques.

**Analyse de l'impact** : Impact critique pour les détenteurs d'actifs numériques et les institutions financières. L'utilisation d'une application de confiance comme vecteur d'exécution permet de contourner les solutions EDR basées sur les signatures de fichiers.

**Recommandations** : 
* Surveiller la création de processus enfants (cmd, powershell, sh) par l'exécutable Obsidian.exe.
* Restreindre ou interdire l'utilisation de plugins tiers non approuvés dans les outils de productivité.
* Rechercher la présence de répertoires suspects comme `.obsidian/plugins/obsidian-shellcommands/data.json`.
* Bloquer les accès réseau sortants vers les explorateurs de blockchain (blockscout.com) depuis les postes de travail, sauf nécessité métier.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | REF6598 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1566.003: Spearphishing via Service <br/> • T1204.002: Malicious File <br/> • T1059.001: PowerShell <br/> • T1102.003: One-Way Communication (Blockchain) |
| Observables & Indicateurs de compromission | ```70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980 (PhantomPull), 195.3.222.251 (Staging), panel.fefea22134.net (C2)``` |

### Source (url) du ou des articles
* https://www.elastic.co/security-labs/phantom-in-the-vault

<br>
<br>
<div id="stardrop-une-attaque-majeure-de-la-supply-chain-npm">```stardrop-une-attaque-majeure-de-la-supply-chain-npm```</div>

## Stardrop Supply Chain Attack Targets Venture Capital Firms, Luxury Brands, and AI Companies
Une campagne massive a été identifiée sur le registre NPM, impliquant plus de 200 packages malveillants publiés depuis le 9 avril. Ces packages utilisent des noms de marques de luxe (Givenchy, Louis Vuitton), de sociétés de capital-risque (Khosla-VC) ou d'outils technologiques populaires (huggingface-cli). Ils prétendent livrer un nouvel agent de codage IA nommé "Stardrop". L'attaque utilise des dépendances optionnelles (optionalDependencies) pour déployer des binaires spécifiques à la plateforme de la victime (Linux, macOS, Windows). Une fois installés via un script `postinstall.mjs`, ces binaires agissent comme des infostealers. Ils ciblent particulièrement les clés d'API OpenAI et Anthropic, ainsi que les identifiants de services cloud (AWS). Bien que NPM supprime rapidement ces packages, ils restent accessibles via de nombreux miroirs globaux.

**Analyse de l'impact** : Risque élevé de fuite de secrets industriels et de compromission de comptes cloud pour les entreprises technologiques et financières. Le ciblage spécifique des clés d'IA suggère une volonté de détournement de ressources ou d'espionnage de modèles.

**Recommandations** : 
* Utiliser des proxys de packages privés pour filtrer les nouveaux paquets NPM non validés.
* Auditer les environnements de développement pour détecter les fichiers `~/.local/share/stardrop/auth.json`.
* Activer la protection contre l'exécution de scripts postinstall non autorisés (`npm install --ignore-scripts`).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1195.001: Compromise Software Dependencies <br/> • T1552: Unsecured Credentials |
| Observables & Indicators of compromise | ```stardrop.dev, p9ia72yajp.us-east-1.awsapprunner.com, 18e8742fb6fb5e70c0c91823d72f5d9074be1d1cba1cbfc0eca75b5427e544da``` |

### Source (url) du ou des articles
* https://opensourcemalware.com/blog/stardrop-attack

<br>
<br>
<div id="escalade-cyber-dans-le-conflit-us-israel-iran"></div>

## Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict
Le conflit entre les États-Unis, Israël et l'Iran a atteint un nouveau sommet le 14 avril 2026. L'échec des pourparlers de paix d'Islamabad et l'annonce d'un blocus naval américain ont déclenché une vague d'opérations cyber offensives. Le groupe Handala prétend avoir détruit 6 pétaoctets de données appartenant à trois départements gouvernementaux de Dubaï (Land, Courts, Roads and Transport). Le groupe hacktiviste pro-iranien Z-PENTEST a publié des preuves techniques de contrôle à distance d'un système de traitement d'eau en Corée du Sud. En Iran, le blackout internet national dure depuis 46 jours, limitant la connectivité à 1% de son niveau normal. Les entreprises technologiques américaines comme Apple, Microsoft et Nvidia sont désormais désignées comme cibles militaires par le CGRI (IRGC).

**Analyse de l'impact** : Risque systémique critique pour les infrastructures d'énergie, de finance et de transport dans le Golfe et les pays alliés des USA. Les attaques passent de l'espionnage à la destruction physique (OT/ICS).

**Recommandations** : 
* Déconnecter immédiatement du réseau internet public tout automate industriel (PLC) ou interface HMI.
* Renforcer les défenses contre les malwares de type "wiper" (sauvegardes hors-ligne régulières).
* Sensibiliser le personnel aux risques accrus de phishing et de social engineering liés au contexte géopolitique.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala, Z-PENTEST Alliance, IRGC |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1485: Data Destruction <br/> • T1491: Defacement <br/> • T0814: Control Device |
| Observables & Indicators of compromise | ```Détails de serveurs PLC exposés (Rockwell), t.me/ax03bot``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://www.recordedfuture.com/research/iran-war-future-scenario-and-business-improvements

<br>
<br>
<div id="analyse-du-patch-tuesday-record-davril-2026"></div>

## Microsoft Patch Tuesday April 2026
Le Patch Tuesday d'avril 2026 est l'un des plus massifs de l'histoire avec 243 vulnérabilités corrigées, dont 78 concernent le moteur Chromium (Edge). Parmi les 165 failles restantes, 8 sont classées comme critiques. La vulnérabilité CVE-2026-32201 (SharePoint Server Spoofing) est activement exploitée dans la nature pour tromper les utilisateurs et voler des informations. Une autre faille critique, CVE-2026-33827, affecte la pile Windows TCP/IP et permet une exécution de code à distance via une condition de course lors du traitement de paquets IPv6. Microsoft a également introduit de nouvelles protections contre l'abus de fichiers `.rdp` malveillants, souvent utilisés par des groupes comme APT29 pour exfiltrer des identifiants et des fichiers locaux via la redirection de ressources.

**Analyse de l'impact** : Impact global sur la quasi-totalité des parcs Windows et SharePoint. Les vecteurs RCE sur la couche réseau (TCP/IP) sont particulièrement dangereux car ils ne nécessitent aucune interaction utilisateur.

**Recommandations** : 
* Prioriser le déploiement des correctifs pour SharePoint (CVE-2026-32201) et Windows Defender (CVE-2026-33825).
* Désactiver IPv6 si non nécessaire pour réduire la surface d'attaque TCP/IP.
* Informer les utilisateurs des nouvelles alertes de sécurité lors de l'ouverture de fichiers RDP.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | APT29 (suspecté sur RDP) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1210: Exploitation of Remote Services <br/> • T1204.002: Malicious File |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/32898
* https://www.bleepingcomputer.com/news/microsoft/microsoft-april-2026-patch-tuesday-fixes-167-flaws-2-zero-days/

<br>
<br>
<div id="breche-chez-rockstar-games-lexfiltration-shinyhunters"></div>

## ShinyHunters claim the hack of Rockstar Games breach and started leaking data
Le groupe ShinyHunters a revendiqué l'intrusion et le vol de 8.1 Go de données appartenant au studio Rockstar Games. Les données auraient été obtenues via une compromission du fournisseur d'analyses cloud Anodot, lui-même lié à Snowflake. L'exfiltration inclut du code source de systèmes anti-cheat, des analyses sur les joueurs, des tickets de support client Zendesk et des informations financières. Alors que Rockstar minimise l'impact en parlant d'informations "non matérielles", les attaquants menacent de provoquer des perturbations numériques supplémentaires si aucune rançon n'est payée. Cet incident illustre la tendance des attaquants à cibler les tiers et les partenaires cloud plutôt que de tenter de forcer les défenses périmétriques directes des entreprises.

**Analyse de l'impact** : Risque de réputation et perte de propriété intellectuelle. Le leak du code anti-cheat pourrait favoriser le développement massif de tricheries pour les titres populaires du studio.

**Recommandations** : 
* Réviser les permissions d'accès accordées aux plateformes tierces d'analyse de données.
* Activer l'authentification multi-facteurs (MFA) obligatoire sur tous les accès Snowflake et SaaS.
* Effectuer une rotation immédiate des secrets et clés d'API partagés avec les partenaires externes.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | ShinyHunters |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1199: Trusted Relationship <br/> • T1537: Transfer Data to Cloud Account |
| Observables & Indicateurs de compromission | ```8.1GB dataset leak (SHA non fourni)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190796/data-breach/shinyhunters-claim-the-hack-of-rockstar-games-breach-and-started-leaking-data.html
* https://c.im/@goss/116405663011206526

<br>
<br>
<div id="campagne-de-malware-via-de-fausses-ia-claude"></div>

## Fake Claude AI installer abuses DLL sideloading to deploy PlugX
Des chercheurs ont découvert un site web frauduleux imitant le site officiel de l'IA "Claude" d'Anthropic. Le site propose au téléchargement une archive ZIP contenant un installeur "pro version". En réalité, le processus installe la version légitime mais utilise une technique de "DLL sideloading" pour charger une bibliothèque malveillante nommée `avk.dll`. Cette DLL, une fois chargée par un exécutable légitime et signé (un updater G DATA), déchiffre un payload contenu dans un fichier `.dat` et déploie le malware PlugX. Ce RAT (Remote Access Trojan) permet un contrôle total de la machine et la modification des paramètres réseau. Pour minimiser sa détection, le script de déploiement utilise un mécanisme d'auto-suppression après infection.

**Analyse de l'impact** : Compromission totale des postes de travail. L'utilisation de thèmes liés à l'IA augmente considérablement le taux de réussite de l'ingénierie sociale auprès des employés cherchant des outils de productivité.

**Recommandations** : 
* Interdire le téléchargement d'exécutables depuis des sources non officielles.
* Surveiller l'utilisation de `WScript.exe` pour l'exécution de scripts VBS suspects dans les dossiers temporaires.
* Rechercher l'indicateur de persistance : `NOVUpdate.exe` présent dans le dossier de démarrage (Startup) de Windows.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (PlugX souvent lié à l'espionnage) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1574.002: DLL Side-Loading <br/> • T1037.001: Logon Script (Startup folder) |
| Observables & Indicators of compromise | ```8.217.190.58 (C2), NOVUpdate.exe, avk.dll``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190754/malware/fake-claude-ai-installer-abuses-dll-sideloading-to-deploy-plugx.html