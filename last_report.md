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
  * [Le groupe teampcp industrialise les attaques sur la supply chain logicielle](#le-groupe-teampcp-industrialise-les-attaques-sur-la-supply-chain-logicielle)
  * [Voidlink : un rootkit hybride linux issu d'un developpement assiste par ia](#voidlink--un-rootkit-hybride-linux-issu-dun-developpement-assiste-par-ia)
  * [Infiltration systemique des travailleurs it nord-coreens dans les entreprises occidentales](#infiltration-systemique-des-travailleurs-it-nord-coreens-dans-les-entreprises-occidentales)
  * [L'emergence de la technique clickfix comme vecteur d'acces initial privilegie](#lemergence-de-la-technique-clickfix-comme-vecteur-dacces-initial-privilegie)
  * [Nasir security intensifie ses cyber-attaques contre les infrastructures energetiques du golfe](#nasir-security-intensifie-ses-cyber-attaques-contre-les-infrastructures-energetiques-du-golfe)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace cyber en mars 2026 est marqué par une intensification critique des attaques sur la « supply chain » logicielle, illustrée par l'opération d'envergure du groupe TeamPCP contre Trivy et LiteLLM. Cette tendance démontre une transition des attaquants vers la compromission systématique des outils de sécurité et de développement eux-mêmes pour atteindre des milliers de cibles. Parallèlement, l'usage de l'intelligence artificielle par les acteurs malveillants devient concret, facilitant le développement itératif de malwares sophistiqués comme le rootkit VoidLink. On observe également une professionnalisation accrue de l'économie de l'extorsion avec l'apparition de plateformes de traitement de données volées telles que « Leak Bazaar ». La technique de social engineering « ClickFix » s'impose comme un vecteur d'accès initial redoutable, contournant les protections des navigateurs en manipulant directement les outils système natifs (PowerShell, Terminal). La menace interne prend une dimension géopolitique majeure avec l'infiltration massive de travailleurs IT nord-coréens utilisant des identités usurpées pour financer le régime de Pyongyang. Enfin, les vulnérabilités critiques affectant les infrastructures (SharePoint, NetScaler, KACE SMA) continuent d'être exploitées quasi immédiatement après leur divulgation. Les décideurs doivent impérativement renforcer la surveillance des environnements de CI/CD et durcir les politiques d'exécution sur les postes de travail.

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
| **Lapsus$** | Santé / Pharmacie | Extorsion, vol de code source et données employés | [Security Affairs](https://securityaffairs.com/189936/data-breach/cybercrime-group-lapsus-claims-the-hack of-pharma-giant-astrazeneca.html) |
| **Nasir Security** | Énergie, Douanes, Gouvernement (Moyen-Orient) | Cyber-espionnage et sabotage, revendications idéologiques (Hezbollah) | [Ransomlook](https://www.ransomlook.io//group/nasir%20security) |
| **NKITW (North Korean IT Workers)** | Technologie, Agences Web (Global) | Fraude à l'emploi, usurpation d'identité, financement du régime via salaires détournés | [Flare](https://flare.io/learn/resources/blog/north-korean-it-worker-employment-fraud) |
| **TeamPCP** | Supply Chain Logicielle (CI/CD), IA | Compromission de jetons d'accès, empoisonnement de paquets (PyPI, GitHub Actions), vol d'identifiants cloud | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-litellm-pypi-supply-chain-attack) / [Kaspersky](https://www.kaspersky.co.uk/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/30159/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :

| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Technologie | Souveraineté US | La FCC interdit l'importation de nouveaux routeurs grand public de fabrication étrangère pour protéger la sécurité nationale. | [Security Affairs](https://securityaffairs.com/189959/security/fcc-targets-foreign-router-imports-amid-rising-cybersecurity-concerns.html) |
| Gouvernemental | Conflit Iran-Israël-USA | Analyse des frappes en Iran et de la position de l'Espagne au sein de l'UE concernant la légalité internationale. | [IRIS](https://www.iris-france.org/guerre-en-iran-lespagne-sauve-t-elle-lhonneur-de-lue-avec-josep-borrell/) |
| Militaire / Cyber-Défense | Guerre des drones (Iran) | Étude du retard des capacités de lutte anti-drones au Royaume-Uni face à l'efficacité des systèmes iraniens (Shahed 136). | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/decade-long-struggle-thwart-irans-drones-carries-warnings-uk) |
| Politique | Corée du Nord | Analyse de la signalétique politique lors du 9ème Congrès du Parti et de la montée en puissance de Kim Ju-ae. | [IRIS](https://www.iris-france.org/the-debate-surrounding-kim-ju-ae-what-matters-isnt-the-successor-but-the-signal/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :

| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| **FCC targets foreign router imports** | Pierluigi Paganini | 25/03/2026 | États-Unis | Secure and Trusted Communications Networks Act | Mise à jour de la « Covered List » incluant les routeurs grand public étrangers, les interdisant de vente aux USA. | [Security Affairs](https://securityaffairs.com/189959/security/fcc-targets-foreign-router-imports-amid-rising-cybersecurity-concerns.html) |
| **Grundschutz++: Mehr Resilienz** | HiSolutions | 25/03/2026 | Allemagne | BSI IT-Grundschutz (NIS-2) | Évolution du référentiel vers le format OSCAL (Compliance as Code) pour automatiser la conformité et la résilience. | [HiSolutions](https://research.hisolutions.com/2026/03/grundschutz-mehr-resilienz-in-der-informationssicherheit/) |
| **Russian national convicted for botnet** | Pierluigi Paganini | 25/03/2026 | États-Unis / Russie | Condamnation pénale (Justice US) | Ilya Angelov condamné à 24 mois de prison pour l'exploitation du botnet TA551 (Mario Kart) utilisé dans des attaques par ransomware. | [Security Affairs](https://securityaffairs.com/189987/cyber-crime/russian-national-convicted-for-running-botnet-used-in-attacks-on-u-s-firms.html) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :

| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Divertissement | **Crunchyroll** | Vol de données client liées aux tickets de support technique, confirmé par l'entreprise. | [DataBreaches.net](https://databreaches.net/2026/03/25/anime-streaming-giant-crunchyroll-says-hacker-stole-data-related-to-customer-service-tickets/) |
| Énergie / Gouvernement | **UAE Customs / Al-Safi Oil** | Revendication de cyber-attaques massives avec accès complet aux données par le groupe Nasir Security. | [Ransomlook](https://www.ransomlook.io//group/nasir%20security) |
| Multi-sectoriel | **Sound Radix** | Compromission d'une plateforme de support client impactant 293 000 adresses emails et noms. | [HIBP](https://haveibeenpwned.com/Breach/SoundRadix) |
| Pharmaceutique | **AstraZeneca** | Revendication par Lapsus$ du vol de 3 Go de données, incluant du code source (Java, Python) et des identifiants. | [Security Affairs](https://securityaffairs.com/189936/data-breach/cybercrime-group-lapsus-claims-the-hack-of-pharma-giant-astrazeneca.html) |
| Services RH | **Navia Benefit Solutions** | Intrusion ayant exposé les données personnelles de 2,7 millions de personnes, dont des employés de HackerOne. | [Security Affairs](https://securityaffairs.com/189969/data-breach/recent-navia-data-breach-impacts-hackerone-employee-data.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).

| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| **CVE-2025-32975** | 10.0 | Quest KACE SMA | Authentication Bypass (SSO) | [Field Effect](https://fieldeffect.com/blog/2025-quest-kace-sma-vulnerability-exploited) |
| **CVE-2026-20963** | 9.8 | Microsoft SharePoint | Remote Code Execution (RCE) - Unauthenticated | [CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-004/) |
| **CVE-2026-33634** | 9.4 | Trivy (Aqua Security) | Supply Chain Poisoning / RCE | [Kaspersky](https://www.kaspersky.co.uk/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/30159/) |
| **CVE-2026-3055** | 9.1 | Citrix NetScaler ADC/Gateway | Memory Overread (semblable à CitrixBleed) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/citrix-urges-admins-to-patch-netscaler-flaws-as-soon-as-possible/) |
| **CVE-2026-33917** | 8.8 | OpenEMR | SQL Injection | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-33917) |
| **CVE-2026-4758** | 8.8 | WP Job Portal (Wordpress) | Arbitrary File Deletion / RCE | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-4758) |
| **CVE-2026-27654** | 8.8 | NGINX (ngx_http_dav_module) | Buffer Overflow | [Security Online](https://securityonline.info/nginx-emergency-security-update-cve-2026-buffer-overflow/) |
| **CVE-2025-15517** | 8.6 | TP-Link Archer NX | Authentication Bypass / Firmware Takeover | [Security Affairs](https://securityaffairs.com/189980/iot/patch-now-tp-link-archer-nx-routers-vulnerable-to-firmware-takeover.html) |
| **CVE-2026-30976** | 8.6 | Sonarr | Path Traversal (Windows) | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-30976) |
| **CVE-2026-21637** | 7.5 | Node.js (TLS SNICallback) | Denial of Service / Remote Process Crash | [CyberSecurityNews](https://cybersecuritynews.com/node-js-patches-multiple-vulnerabilities/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| **ClickFix Campaigns Targeting Windows and macOS** | Analyse détaillée d'un vecteur d'attaque montant contournant les EDR. | [Recorded Future](https://www.recordedfuture.com/research/clickfix-campaigns-targeting-windows-and-macos) |
| **Illuminating VoidLink: Technical analysis of the rootkit** | Cas d'école de développement de malware assisté par IA et hybride LKM/eBPF. | [Elastic Security Labs](https://www.elastic.co/security-labs/illuminating-voidlink) |
| **North Korean IT Worker Employment Fraud** | Menace cyber-humaine structurelle pour les entreprises occidentales. | [Flare](https://flare.io/learn/resources/blog/north-korean-it-worker-employment-fraud) |
| **TeamPCP Hijacks LiteLLM's PyPI Package** | Attaque supply chain majeure impactant l'écosystème de l'IA. | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-litellm-pypi-supply-chain-attack) |
| **UAE Customs - ACCESS GRANTED ! By nasir security** | Activité d'un groupe Hacktiviste/étatique ciblant les infrastructures critiques. | [Ransomlook](https://www.ransomlook.io//group/nasir%20security) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| **Apple Patches (almost) everything again** | Mise à jour de sécurité de routine, traitée dans la synthèse des vulnérabilités. | [SANS ISC](https://isc.sans.edu/diary/rss/32830) |
| **Enabling Auditing, Logging in Google Cloud** | Article purement pédagogique/éducatif sans menace immédiate spécifique. | [Cyber Engage](https://www.cyberengage.org/post/enabling-auditing-logging-and-log-explorer-in-google-cloud) |
| **GitHub adds AI-powered bug detection** | Annonce produit de défense, moins prioritaire que les menaces actives. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/github-adds-ai-powered-bug-detection-to-expand-security-coverage/) |
| **Kali Linux 2026.1 released** | Actualité sur les outils offensive security, pas une menace cyber en soi. | [BleepingComputer](https://www.bleepingcomputer.com/news/linux/kali-linux-20261-released-with-8-new-tools-new-backtrack-mode/) |
| **Paid AI Accounts Are Now a Commodity** | Phénomène de marché souterrain déjà bien connu. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/paid-ai-accounts-are-now-a-hot-underground-commodity/) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="le-groupe-teampcp-industrialise-les-attaques-sur-la-supply-chain-logicielle"></div>

## Le groupe teampcp industrialise les attaques sur la supply chain logicielle
Le groupe TeamPCP a mené une série d'attaques dévastatrices contre la chaîne d'approvisionnement logicielle, ciblant les outils Trivy (Aqua Security), Checkmarx et la bibliothèque LiteLLM. En compromettant des jetons d'accès GitHub et des comptes PyPI, les attaquants ont injecté du code malveillant dans des versions officielles (LiteLLM 1.82.7/8). Le malware, surnommé "TeamPCP Cloud Stealer", utilise des fichiers `.pth` pour s'exécuter automatiquement à chaque démarrage de l'interpréteur Python, volant les identifiants AWS, GCP, Azure, ainsi que les secrets Kubernetes et les clés SSH. L'attaque sur Trivy a consisté à détourner des tags de versions de GitHub Actions pour rediriger les utilisateurs vers des commits malveillants. Une caractéristique alarmante est la capacité du malware à détruire des clusters Kubernetes s'il détecte des paramètres régionaux iraniens (Farsi/Tehran). Des centaines de milliers de comptes auraient été compromis selon les attaquants. La rapidité d'exécution et la persistance via des services système (`sysmon.service`) démontrent un haut niveau de technicité.

**Analyse de l'impact** : Impact critique sur la supply chain logicielle mondiale ; risque de fuite massive d'identifiants cloud et de destruction d'infrastructures Kubernetes.

**Recommandations** : Épingler les versions des GitHub Actions via des hash SHA plutôt que des tags. Activer le MFA matériel pour tous les comptes de publication de paquets (PyPI, npm). Rechercher la présence du fichier `litellm_init.pth` dans les répertoires `site-packages`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (alias DeadCatx3, PCPcat, CanisterWorm) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise: Software Dependencies<br/>* T1574.006: Hijack Execution Flow: LD_PRELOAD<br/>* T1053.003: Scheduled Task/Job: Systemd Service |
| Observables & Indicateurs de compromission | * `models.litellm.cloud`<br/>* `scan.aquasecurtiy.org`<br/>* `checkmarkr.zone`<br/>* Hash SHA256 (litellm_init.pth): `ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg` |

### Source (url) du ou des articles
* https://opensourcemalware.com/blog/teampcp-litellm-pypi-supply-chain-attack
* https://www.kaspersky.co.uk/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/30159/

<br>
<br>

<div id="voidlink--un-rootkit-hybride-linux-issu-dun-developpement-assiste-par-ia"></div>

## Voidlink : un rootkit hybride linux issu d'un developpement assiste par ia
Elastic Security Labs a analysé VoidLink, un framework de malware Linux sophistiqué dont le développement semble avoir été massivement assisté par IA (via l'IDE TRAE). Ce rootkit utilise une architecture hybride inédite combinant un module de noyau chargé (LKM) et des programmes eBPF pour assurer une furtivité maximale. Le LKM gère la manipulation du noyau et le masquage de processus via le hook de l'appel système `getdents64`, tandis que l'eBPF est dédié au masquage des connexions réseau en interceptant l'outil `ss` (Netlink). Le malware se déguise en pilote AMD légitime (`amd_mem_encrypt`) et implémente des techniques d'anti-forensics, comme un délai d'initialisation de 3 secondes pour tromper les scanners au chargement. Il dispose d'un canal C2 furtif basé sur des paquets ICMP Echo Request modifiés. Les commentaires dans le code source, structurés comme des conversations avec une IA, confirment cette nouvelle méthode de développement cybercriminel.

**Analyse de l'impact** : Menace persistante et hautement furtive pour les serveurs Linux en environnement cloud, difficilement détectable par les outils de surveillance classiques.

**Recommandations** : Appliquer le mode « Kernel Lockdown » sur Linux. Surveiller l'utilisation du helper eBPF `bpf_probe_write_user`. Utiliser des outils de forensics mémoire pour détecter les hooks ftrace non déclarés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteur d'expression chinoise (non nommé spécifiquement, lié à infrastructure Alibaba Cloud) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1014: Rootkit<br/>* T1547.006: Boot or Logon Autostart Execution: Kernel Modules and Extensions<br/>* T1105: Ingress Tool Transfer (via ICMP) |
| Observables & Indicateurs de compromission | * `8.149.128.10`<br/>* `116.62.172.147`<br/>* Fichier: `vl_stealth.ko`<br/>* Commande ICMP magique: `0xC0DE` |

### Source (url) du ou des articles
* https://www.elastic.co/security-labs/illuminating-voidlink

<br>
<br>

<div id="infiltration-systemique-des-travailleurs-it-nord-coreens-dans-les-entreprises-occidentales"></div>

## Infiltration systemique des travailleurs it nord-coreens dans les entreprises occidentales
Une recherche conjointe de Flare et IBM X-Force révèle l'ampleur de l'infiltration de travailleurs IT nord-coréens (NKITW) au sein des entreprises occidentales. Ces agents utilisent des identités usurpées et des collaborateurs occidentaux (prête-noms) pour obtenir des postes de développeurs à distance, générant plus de 500 millions de dollars par an pour le régime de Pyongyang. Leurs méthodes incluent l'utilisation de l'IA pour créer de faux profils LinkedIn et GitHub, ainsi que RoomGPT pour falsifier leurs arrière-plans lors d'appels vidéo. Une fois embauchés, ils se concentrent sur la génération de revenus, bien que certains groupes aient été liés à des vols de données ou de cryptomonnaies. Des indicateurs forensiques incluent l'utilisation massive de Google Translate (anglais vers coréen) et la présence de logiciels spécifiques comme `NetKey` ou `OConnect` sur leurs postes de travail. Les engagements se terminent souvent par des licenciements pour mauvaise performance après quelques mois, avant que l'agent ne recommence avec une nouvelle identité.

**Analyse de l'impact** : Risque financier (financement d'États sous sanctions), risque de fuite de données et compromission d'infrastructure par des insiders.

**Recommandations** : Renforcer les procédures d'onboarding avec vérification d'identité par appel vidéo direct. Rechercher les traces de logiciels VPN/Proxy nord-coréens sur les postes de travail. Sensibiliser les RH aux incohérences de CV et de communication.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | North Korean IT Workers (NKITW), potentiellement lié à l'entité sanctionnée Ryonbong |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566: Phishing (Social Engineering pour l'embauche)<br/>* T1078: Valid Accounts (Obtenus via recrutement frauduleux)<br/>* T1132: Data Encoding (Caché derrière du trafic VPN) |
| Observables & Indicateurs de compromission | * Logiciels: NetKey, OConnect, IP Messenger<br/>* Chemins de fichiers: `rb corp`, `STN Corp`<br/>* Domaines: `.kp` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/north-korean-it-worker-employment-fraud

<br>
<br>

<div id="lemergence-de-la-technique-clickfix-comme-vecteur-dacces-initial-privilegie"></div>

## L'emergence de la technique clickfix comme vecteur d'acces initial privilegie
Depuis mai 2024, une montée en puissance de la technique de social engineering « ClickFix » est observée, ciblant tant Windows que macOS. Les attaquants utilisent des leurres visuels (faux reCAPTCHA, notifications de mise à jour ou de nettoyage de stockage) pour manipuler les utilisateurs afin qu'ils copient et exécutent manuellement une commande malveillante dans leur terminal ou la boîte de dialogue "Exécuter" de Windows. Cette méthode de « pastejacking » permet de charger des malwares directement en mémoire (Living-off-the-Land), contournant les protections natives des navigateurs. Cinq clusters distincts ont été identifiés, usurpant des marques comme QuickBooks, Booking.com ou Birdeye. Les charges utiles finales incluent souvent des RAT (NetSupport, Remcos) ou des infostealers (Lumma, StealC). La sophistication technique s'accroît avec la détection automatique de l'OS pour servir le bon script (Bash/Zsh pour Mac, PowerShell pour Windows).

**Analyse de l'impact** : Risque élevé d'infection des postes de travail par des agents tiers, bypassant les solutions de sécurité périmétriques et de navigation.

**Recommandations** : Désactiver le raccourci Win+R via GPO. Implémenter le mode "Constrained Language" pour PowerShell. Sensibiliser les utilisateurs à ne jamais copier-coller de commandes provenant d'un site web dans un terminal.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | SmartApeSG, BlueDelta (APT28), PurpleBravo (Corée du Nord) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1059.001: Command and Scripting Interpreter: PowerShell<br/>* T1204.002: User Execution: Malicious File/Command<br/>* T1027: Obfuscated Files or Information |
| Observables & Indicateurs de compromission | * Domaines: `nobovcs.com`, `checkpulses.com`, `alababababa.cloud`<br/>* IPs: `62.164.177.230`, `152.89.244.70` |

### Source (url) du ou des articles
* https://www.recordedfuture.com/research/clickfix-campaigns-targeting-windows-and-macos
* https://isc.sans.edu/diary/rss/32826

<br>
<br>

<div id="nasir-security-intensifie-ses-cyber-attaques-contre-les-infrastructures-energetiques-du-golfe"></div>

## Nasir Security intensifie ses cyber-attaques contre les infrastructures energetiques du golfe
Le groupe pro-iranien Nasir Security (revendiquant une affiliation au Hezbollah) a publié une série de revendications concernant des cyber-attaques réussies contre des entités majeures au Moyen-Orient. Parmi les victimes figurent les Douanes des Émirats Arabes Unis (Federal Customs Authority), ainsi que plusieurs compagnies pétrolières dont Al-Safi Oil (Irak), Rumaila Operating Organisation et Dubai Petroleum. Le groupe affirme avoir maintenu un accès persistant ("comme un fantôme") sur ces réseaux pendant plusieurs mois avant d'annoncer sa présence. Les données exfiltrées contiendraient des informations critiques liées à la sécurité nationale, incluant des liens avec des entreprises israéliennes (Elbit Systems, Mossad). Leurs publications sur le dark web servent à la fois d'outil d'extorsion et de propagande idéologique, menaçant de divulguer davantage de preuves si leurs adversaires ne reconnaissent pas leur vulnérabilité.

**Analyse de l'impact** : Menace sérieuse sur l'intégrité des infrastructures critiques du Golfe et risque d'espionnage industriel/étatique à grande échelle.

**Recommandations** : Renforcer la segmentation réseau entre les environnements IT et OT. Mener des audits de compromission approfondis (Compromise Assessment) sur les réseaux gouvernementaux et énergétiques de la région.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Nasir Security (pro-iranien / Hezbollah Lebanon) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application<br/>* T1071.001: Application Layer Protocol: Web Protocols<br/>* T1567: Exfiltration Over Web Service |
| Observables & Indicateurs de compromission | * URL .onion: `yzcpwxuhbkyjnyn4qsf4o5dkvu6m2fyo7dwizmnlutanlmzlos7pa6qd.onion`<br/>* Site: `nasir.cc` |

### Source (url) du ou des articles
* https://www.ransomlook.io//group/nasir%20security