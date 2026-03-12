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
  * [Panorama de la cybermenace 2025](#panorama-de-la-cybermenace-2025)
  * [Attaque destructrice du groupe Handala contre Stryker](#attaque-destructrice-du-groupe-handala-contre-stryker)
  * [Campagne PhantomRaven : empoisonnement de la chaîne d'approvisionnement NPM](#campagne-phantomraven-empoisonnement-de-la-chaine-dapprovisionnement-npm)
  * [Malware via de fausses publicités "Claude Code"](#malware-via-de-fausses-publicites-claude-code)
  * [Sécurité des agents IA autonomes (Agentic AI)](#securite-des-agents-ia-autonomes-agentic-ai)
  * [KadNap : botnet furtif ciblant les routeurs Asus](#kadnap-botnet-furtif-ciblant-les-routeurs-asus)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de ce début d'année 2026 est marqué par une érosion définitive des frontières entre activisme pro-étatique et cybercriminalité pure, illustrée par l'attaque d'envergure contre Stryker. L'émergence de "Gulf War III" suite aux tensions entre les États-Unis, Israël et l'Iran transforme le cyberespace en champ de bataille de représailles directes, où les entreprises technologiques deviennent des cibles de "wiper" par procuration. Parallèlement, l'industrialisation des attaques sur la chaîne d'approvisionnement (NPM, routeurs domestiques) démontre une volonté d'exfiltration massive de données de développement pour compromettre les infrastructures futures. L'intelligence artificielle devient un double vecteur : outil de découverte de vulnérabilités critiques pour les défenseurs, mais aussi appât sophistiqué pour des campagnes de malvertising ciblant les profils techniques. Les vulnérabilités des équipements de bordure (Edge) restent le point d'entrée privilégié, exploitées avec une rapidité accrue par des botnets P2P complexes comme KadNap. La mise en œuvre du Cyber Resilience Act (CRA) devient un impératif stratégique pour les organisations face à ces menaces systémiques. Les décideurs doivent anticiper des perturbations globales de la logistique maritime et médicale dues à ces interférences géopolitiques. La résilience passera désormais par une gestion hybride stricte des identités et un durcissement des accès aux outils d'automatisation comme n8n.
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
| **Handala (Hatef/Void Manticore)** | Santé, Medtech, Infrastructures critiques | Vol de données, utilisation abusive de MDM (Intune) pour effacement à distance (wiper). | https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/ |
| **PhantomRaven** | Développeurs, JavaScript/NPM | Empoisonnement de paquets NPM, Remote Dynamic Dependencies (RDD). | https://www.bleepingcomputer.com/news/security/new-phantomraven-npm-attack-wave-steals-dev-data-via-88-packages/ |
| **VoidLink** | Organisations diverses | Utilisation d'agents IA autonomes pour des opérations malveillantes. | https://blog.talosintelligence.com/agentic-ai-security-why-you-need-to-know-about-autonomous-agents-now/ |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Santé / Medtech | Conflit Iran-USA/Israël | Attaque wiper contre Stryker en représailles à des frappes militaires américaines. | https://www.lemonde.fr/pixels/article/2026/03/11/des-pirates-pro-iraniens-revendiquent-une-importante-cyberattaque-d-une-entreprise-medicale-americaine_6670550_4408996.html |
| Transport Maritime | Conflit Moyen-Orient | Risque de récession mondiale et blocage des routes maritimes en Asie suite à "Gulf War III". | https://www.rusi.org/explore-our-research/publications/commentary/gulf-war-iii-warning-about-effects-taiwan-straits-war-i |
| Défense / Nucléaire | Souveraineté Européenne | Vision de Macron sur la "dissuasion avancée" pour protéger les alliés européens face à la menace russe. | https://www.rusi.org/explore-our-research/publications/commentary/macron-offers-promising-vision-nuclear-deterrence-europe |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Biking the CRA with Balena | Harald Fischer | 11/03/2026 | Union Européenne | Cyber Resilience Act (CRA) | Obligations de gestion des risques cyber, documentation technique et responsabilité des produits Open Source. | https://openssf.org/blog/2026/03/11/first-steps-towards-cyber-resilience-act-conformity-biking-the-cra-with-balena-at-fosdem-2026/ |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Développement logiciel | Développeurs NPM | Exfiltration de jetons CI/CD (.npmrc, .gitconfig) et variables d'environnement via 88 paquets malveillants. | https://www.bleepingcomputer.com/news/security/new-phantomraven-npm-attack-wave-steals-dev-data-via-88-packages/ |
| Santé / Medtech | Stryker | Exfiltration revendiquée de 50 To de données critiques avant effacement des systèmes. | https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-offline-after-iran-linked-wiper-malware-attack/ |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité.
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-27591 | 9.9 | Winter CMS | Escalade de privilèges (Authenticated Backend) | https://cvefeed.io/vuln/detail/CVE-2026-27591 |
| CVE-2025-66956 | 9.9 | Asseco SEE Live 2.0 | Contrôle d'accès incorrect / Exécution d'attachements | https://cvefeed.io/vuln/detail/CVE-2025-66956 |
| CVE-2026-23813 | 9.8 | HPE Aruba AOS-CX | Contournement d'authentification (Web Management) | https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0262/ |
| CVE-2026-32136 | 9.8 | AdGuard Home | Contournement d'authentification via h2c Upgrade | https://cvefeed.io/vuln/detail/CVE-2026-32136 |
| CVE-2026-21536 | 9.8 | Windows (Devices Pricing) | Exécution de code à distance (Découvert par IA) | https://krebsonsecurity.com/2026/03/microsoft-patch-tuesday-march-2026-edition/ |
| CVE-2025-68613 | 9.8 | n8n (Workflow Automation) | Exécution de code à distance (RCE) activement exploitée | https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-n8n-rce-flaw-exploited-in-attacks/ |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Agentic AI security: Why you need to know about autonomous agents now | Analyse prospective essentielle sur les risques liés aux agents IA autonomes. | https://blog.talosintelligence.com/agentic-ai-security-why-you-need-to-know-about-autonomous-agents-now/ |
| KadNap bot compromises 14,000+ devices to route malicious traffic | Analyse technique d'un botnet P2P sophistiqué ciblant les routeurs Asus. | https://securityaffairs.com/189251/malware/kadnap-bot-compromises-14000-devices-to-route-malicious-traffic.html |
| Medtech giant Stryker offline after Iran-linked wiper malware attack | Cas d'étude majeur de wiper pro-étatique impactant une infrastructure de santé globale. | https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-offline-after-iran-linked-wiper-malware-attack/ |
| New PhantomRaven NPM attack wave steals dev data via 88 packages | Alerte critique sur la compromission de la chaîne d'approvisionnement des développeurs JS. | https://www.bleepingcomputer.com/news/security/new-phantomraven-npm-attack-wave-steals-dev-data-via-88-packages/ |
| Panorama de la cybermenace 2025 | Rapport de référence de l'ANSSI sur les tendances stratégiques actuelles. | https://www.cert.ssi.gouv.fr/cti/CERTFR-2026-AVI-0259/ |
| Windows and macOS Malware Spreads via Fake “Claude Code” Google Ads | Exemple concret de social engineering utilisant l'IA comme leurre pour infecter des profils techniques. | https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Thursday, March 12th, 2026 | Contenu audio sans résumé textuel détaillé exploitable. | https://isc.sans.edu/diary/rss/32790 |
| Spinning complex ideas into clear docs with Kri Dontje | Interview centrée sur la communication technique, sans menace cyber directe. | https://blog.talosintelligence.com/spinning-complex-ideas-into-clear-docs-with-kri-dontje/ |
| Vertrauen im digitalen Zeitalter | Commentaire général sur la confiance numérique sans données techniques spécifiques. | https://research.hisolutions.com/2026/03/vertrauen-im-digitalen-zeitalter/ |
| WhatsApp introduces parent-managed accounts for pre-teens | Actualité de fonctionnalité produit, impact limité sur la menace entreprise. | https://www.bleepingcomputer.com/news/security/whatsapp-introduces-parent-managed-accounts-for-pre-teens/ |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="panorama-de-la-cybermenace-2025"></div>

## Panorama de la cybermenace 2025
L'ANSSI (CERT-FR) publie son rapport annuel soulignant l'érosion des frontières entre attaquants étatiques et cybercriminels. Les groupes liés à la Russie et à la Chine intensifient leurs efforts d'espionnage contre les réseaux diplomatiques mondiaux. Le détournement d'outils légitimes et de services cloud devient la norme, compliquant les processus d'imputation. Les équipements de bordure (firewalls, passerelles) sont massivement ciblés par l'exploitation de vulnérabilités Zero-Day ou n-day. On observe un glissement significatif du ransomware classique vers l'exfiltration pure de données, jugée plus discrète et lucrative. L'ingénierie sociale évolue pour inclure des faux supports informatiques plus sophistiqués. L'IA générative commence à être intégrée dans les arsenaux offensifs sans toutefois créer de rupture technologique majeure immédiate. Les tensions géopolitiques exacerbent les cyberattaques destructrices contre les infrastructures critiques. L'ANSSI appelle à une vigilance accrue sur les solutions exposées sur Internet. La coopération internationale reste l'outil principal pour contrer les fuites de données affectant les acteurs malveillants eux-mêmes.

**Analyse de l'impact** : Impact stratégique majeur sur la confiance dans les outils de bordure et les services cloud. L'impossibilité de distinguer clairement les mobiles (crime vs espionnage) complexifie la réponse aux incidents.

**Recommandations** : 
* Prioriser le déploiement de correctifs sur les équipements exposés (Edge) sous 24h.
* Mettre en œuvre une stratégie "Zero Trust" stricte pour les accès administratifs cloud.
* Renforcer la surveillance des exfiltrations massives de données via des outils de DLP.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Groupes liés à la Russie et à la Chine (non nommés spécifiquement dans le résumé) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1020: Automated Exfiltration <br/> * T1566: Phishing |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni dans ce rapport de synthèse.``` |

### Source (url) du ou des articles
* https://www.cert.ssi.gouv.fr/cti/CERTFR-2026-CTI-002/

<br>
<br>

<div id="attaque-destructrice-du-groupe-handala-contre-stryker"></div>

## Attaque destructrice du groupe Handala contre Stryker
Le géant des équipements médicaux Stryker a subi une attaque dévastatrice par le groupe pro-iranien Handala. Les pirates affirment avoir exfiltré 50 To de données sensibles avant de déclencher un "wiper" sur plus de 200 000 systèmes. L'attaque aurait exploité la solution Microsoft Intune pour envoyer des commandes d'effacement à distance aux appareils connectés, y compris les mobiles des employés. Les opérations mondiales de Stryker dans 79 pays ont été paralysées, forçant un retour aux procédures papier. L'incident est présenté comme une mesure de représailles après des frappes américaines en Iran. Le groupe a défacé les pages de connexion Entra ID avec son logo. Stryker a confirmé l'incident via un formulaire SEC 8-K, admettant une perturbation mondiale de son environnement Microsoft. Les hôpitaux clients rapportent des difficultés d'approvisionnement en matériel chirurgical. Handala est lié au Ministère iranien du Renseignement (MOIS) et est connu pour ses opérations de guerre psychologique. L'utilisation malveillante d'outils d'administration légitimes (Living Off the Land) est ici centrale.

**Analyse de l'impact** : Rupture critique de la chaîne d'approvisionnement médicale mondiale. L'utilisation des outils de MDM (Intune) comme vecteur de destruction crée un précédent alarmant pour la gestion des flottes d'appareils mobiles.

**Recommandations** : 
* Segmenter strictement les droits d'administration sur les consoles MDM (MFA obligatoire, approbation multi-utilisateurs).
* Auditer les logs Intune/Entra pour détecter des commandes d'effacement massif ("Wipe") anormales.
* Désinstaller temporairement les profils de gestion d'entreprise sur les appareils personnels (BYOD) en cas de suspicion de compromission du tenant.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala (Void Manticore / Hatef) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1078.004: Cloud Accounts <br/> * T1485: Data Destruction <br/> * T1566.002: Spearphishing Link |
| Observables & Indicateurs de compromission | ```* Logo Handala sur pages de connexion Entra ID <br/> * Commandes de remote wipe via Microsoft Intune``` |

### Source (url) du ou des articles
* https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/
* https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-offline-after-iran-linked-wiper-malware-attack/

<br>
<br>

<div id="campagne-phantomraven-empoisonnement-de-la-chaine-dapprovisionnement-npm"></div>

## Campagne PhantomRaven : empoisonnement de la chaîne d'approvisionnement NPM
La campagne "PhantomRaven" frappe le registre npm avec 88 nouveaux paquets malveillants ciblant les développeurs JavaScript. Ces paquets utilisent la technique "Remote Dynamic Dependencies" (RDD) pour contourner l'analyse statique automatique. Le fichier `package.json` appelle une dépendance externe via une URL, téléchargeant le malware uniquement lors de l'exécution de `npm install`. Le but principal est l'exfiltration de données de configuration sensibles : `.gitconfig`, `.npmrc` et variables d'environnement. Les jetons CI/CD pour GitHub, GitLab et Jenkins sont spécifiquement visés. La campagne utilise le "slopsquatting", imitant des projets populaires comme Babel ou GraphQL avec des noms générés par IA. L'infrastructure d'attaque repose sur des serveurs Amazon EC2 utilisant des noms de domaine liés au mot "artifact". Les données volées sont envoyées via des requêtes HTTP GET/POST ou des WebSockets vers un serveur C2. Plus de 80 paquets malveillants seraient encore actifs sur le registre. Les chercheurs notent une rotation fréquente des comptes jetables pour publier ces paquets.

**Analyse de l'impact** : Risque majeur de compromission en cascade des environnements de production via le vol de secrets de développement et de déploiement (CI/CD).

**Recommandations** : 
* Utiliser des fichiers de verrouillage (`package-lock.json`) et auditer systématiquement les nouvelles dépendances.
* Interdire les installations npm sans validation préalable des URL de dépendances externes au niveau du proxy.
* Faire pivoter immédiatement tous les jetons CI/CD si un paquet suspect a été installé.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | PhantomRaven |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.001: Supply Chain Compromise: Dependencies <br/> * T1552.001: Credentials In Files <br/> * T1071.001: Web Protocols |
| Observables & Indicateurs de compromission | ```* Domaines contenant "artifact" sur AWS EC2 <br/> * Appels externes dans package.json vers des URL non-npm <br/> * Exfiltration vers des endpoints PHP modifiés``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-phantomraven-npm-attack-wave-steals-dev-data-via-88-packages/

<br>
<br>

<div id="malware-via-de-fausses-publicites-claude-code"></div>

## Malware via de fausses publicités "Claude Code"
Bitdefender a détecté une campagne malveillante via Google Ads ciblant les utilisateurs recherchant "Claude Code" d'Anthropic. Les publicités redirigent vers des sites contrefaits hébergés sur Squarespace mimant la documentation officielle. L'attaque utilise la tactique "ClickFix" : les victimes sont incitées à copier-coller des commandes terminal pour l'installation. Sur Windows, la commande abuse de `mshta.exe` pour télécharger un stealer (Trojan.Stealer.GJ). Sur macOS, un script complexe décode une charge utile en Base64 pour installer une porte dérobée Mach-O. Cette backdoor permet l'exécution de commandes à distance et le vol de données de navigateur et de cryptomonnaies. Les attaquants auraient compromis un compte publicitaire légitime appartenant à une entreprise malaisienne pour passer les filtres de Google. Aucun exploit technique n'est utilisé ; l'infection repose entièrement sur l'ingénierie sociale et la confiance envers les résultats sponsorisés. Les binaires macOS effectuent des vérifications anti-sandbox et anti-VM. La charge utile macOS présente des similitudes avec le stealer AMOS.

**Analyse de l'impact** : Compromission directe des postes de travail des développeurs et analystes de données, avec accès complet au système de fichiers et aux identifiants.

**Recommandations** : 
* Sensibiliser les utilisateurs à ne jamais copier-coller des commandes terminal provenant de sites non vérifiés.
* Bloquer l'exécution de `mshta.exe` via des politiques de restriction logicielle (AppLocker/WDAC).
* Utiliser un bloqueur de publicités au niveau de l'entreprise pour filtrer les résultats sponsorisés.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (Similitudes avec AMOS) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.002: User Execution: Malicious File <br/> * T1059.001: PowerShell <br/> * T1218.005: Mshta |
| Observables & Indicateurs de compromission | ```* hxxps://download.active-version[.]com/claude <br/> * hxxps://claude-code-cmd.squarespace[.]com <br/> * SHA256: 3b4d3a59024f14cf1f07395afd6957be05d125e00ae8fdcea3a5dee1d8ab9dd3``` |

### Source (url) du ou des articles
* https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware

<br>
<br>

<div id="securite-des-agents-ia-autonomes-agentic-ai"></div>

## Sécurité des agents IA autonomes (Agentic AI)
Cisco Talos alerte sur les risques émergents liés au déploiement des agents IA autonomes dans les entreprises. Ces systèmes, capables de planifier et d'exécuter des tâches avec des outils réels, introduisent de nouvelles surfaces d'attaque. Un agent compromis pourrait causer des dommages supérieurs à un utilisateur humain en raison de sa vitesse d'exécution. Les vulnérabilités incluent la fuite de données lors de requêtes web et la manipulation de l'agent par des instructions externes. Le caractère non-déterministe des LLM rend les approches classiques d'autorisation/blocage insuffisantes. Talos préconise une supervision par des modèles tiers ("Safety models") pour évaluer les conséquences avant exécution. Les attaquants utilisent déjà des frameworks comme VoidLink pour automatiser l'exploration et l'exfiltration. À l'avenir, des agents autonomes pourraient être déployés localement chez la victime pour agir via des "covert channels" asynchrones. Le threat modeling doit désormais intégrer les privilèges spécifiques accordés aux identités machine gérées par l'IA. La traçabilité et l'auditabilité des actions de l'agent sont des impératifs réglementaires.

**Analyse de l'impact** : Risque systémique de perte de contrôle sur les processus automatisés, pouvant mener à des destructions de données massives ou des fuites d'informations confidentielles à l'insu des opérateurs.

**Recommandations** : 
* Appliquer le principe du moindre privilège aux jetons d'accès (API keys) utilisés par les agents IA.
* Mettre en place un "Human-in-the-loop" pour la validation des étapes critiques (suppression, modification de config).
* Isoler les environnements d'exécution des agents dans des bacs à sable (sandboxing) réseau stricts.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Utilisateurs de VoidLink |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1059: Command and Scripting Interpreter <br/> * T1020: Automated Exfiltration <br/> * T1568: Dynamic Resolution |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique fourni (Analyse stratégique)``` |

### Source (url) du ou des articles
* https://blog.talosintelligence.com/agentic-ai-security-why-you-need-to-know-about-autonomous-agents-now/

<br>
<br>

<div id="kadnap-botnet-furtif-ciblant-les-routeurs-asus"></div>

## KadNap : botnet furtif ciblant les routeurs Asus
Lumen Technologies a identifié le botnet "KadNap" ayant compromis plus de 14 000 routeurs Asus, principalement aux États-Unis. Ce botnet utilise une version personnalisée du protocole P2P Kademlia pour masquer ses serveurs de commande et contrôle (C2). Les appareils infectés servent de relais de proxy via un service nommé "Doppelganger", possiblement lié au réseau Faceless. L'infection débute par un script malveillant qui télécharge un binaire ELF (ARM/MIPS) sur l'équipement de bordure. Le malware synchronise son horloge via NTP et génère des identifiants uniques pour rejoindre le réseau DHT. Contrairement à un réseau P2P classique, KadNap maintient des nœuds persistants pour garder le contrôle du réseau. Ces routeurs compromis sont revendus pour mener des attaques par force brute ou des exploitations ciblées. La furtivité est renforcée par la redirection des entrées/sorties vers `/dev/null`. Le botnet est actif depuis août 2025 et continue de croître. Plus de 60 % des victimes se situent aux États-Unis, suivis par Taïwan et l'Europe.

**Analyse de l'impact** : Création d'une infrastructure de proxy résidentiel massive permettant aux attaquants de masquer l'origine de leurs assauts derrière des IP légitimes de confiance.

**Recommandations** : 
* Mettre à jour le firmware des routeurs Asus et désactiver l'administration à distance.
* Surveiller les communications sortantes inhabituelles vers les ports non-standards ou le trafic UDP lié au DHT.
* Réinitialiser les équipements suspects et changer les mots de passe d'administration par défaut.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs de Doppelganger (ex-Faceless/TheMoon) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1090.002: External Proxy <br/> * T1584.005: Botnet <br/> * T1201: Password Policy Discovery |
| Observables & Indicateurs de compromission | ```* IP: 45.135.180.38 <br/> * IP: 45.135.180.177 <br/> * Binaire ELF (ARM/MIPS) furtif``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189251/malware/kadnap-bot-compromises-14000-devices-to-route-malicious-traffic.html