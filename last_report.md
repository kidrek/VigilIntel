{
"FR": {
    "Analyse transversale": {
        "analyse": "L'analyse des menaces révèle une intensification des tactiques d'espionnage sophistiquées, notamment le groupe lié à l'Iran UNC1549, qui exploite les relations de confiance (chaîne d'approvisionnement, tiers) et utilise des outils personnalisés pour garantir une persistance à long terme et une furtivité élevée (DCSync, reverse SSH). Simultanément, la menace du ransomware continue d'évoluer, le groupe Akira se concentrant désormais sur les infrastructures de virtualisation avancées comme Nutanix AHV pour maximiser l'impact. L'exploitation des vulnérabilités critiques (RCE dans XWiki, SAP, IBM AIX) reste une tactique privilégiée par les botnets (RondoDox) et les acteurs de la menace pour obtenir un accès initial. Un point marquant est la montée en puissance de l'utilisation de l'Intelligence Artificielle (IA) par les acteurs malveillants, notamment APT28 et PROMPTFLUX, pour développer des malwares adaptatifs et améliorer les techniques d'évasion. L'actualité est également marquée par plusieurs violations de données majeures affectant les services gouvernementaux (Urssaf/Pajemploi en France, eVisa en Somalie) et le secteur privé (Eurofiber, Jaguar Land Rover), soulignant la criticité des données d'identité et l'impact économique direct des cyberattaques. L'état général des menaces est caractérisé par l'évolution rapide des TTPs des acteurs parrainés par des États et des cybercriminels, l'accent étant mis sur les maillons faibles de la chaîne logistique et l'utilisation de nouvelles technologies d'évasion.",
        "date": "2025-11-18"
    },
    "Synthèse des acteurs malveillants": [
        {
            "nom": "UNC1549",
            "secteur": "Aérospatiale, Défense, Aviation, Tiers de confiance",
            "modop": "Espionnage via compromission des relations de confiance (tiers), hameçonnage ciblé, détournement de l'ordre de recherche DLL (SOH) pour l'exécution de backdoors personnalisées (TWOSTROKE, DEEPROOT, LIGHTRAIL), attaque DCSync, tunnels SSH inversés pour le C2.",
            "tags": [
                "actor",
                "theat_actor",
                "espionnage",
                "iran_nexus",
                "supply_chain",
                "persistence",
                "dll_hijacking",
                "rdp_abuse"
            ],
            "sources": [
                "https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense/"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Akira Ransomware (Storm-1567, Howling Scorpius, Punk Spider, Gold Sahara)",
            "secteur": "Industrie manufacturière, Éducation, TI, Santé, Finance, Agriculture",
            "modop": "Attaques de rançongiciel à double extorsion. Accès initial via vulnérabilités SonicWall ou Veeam. Cible les infrastructures de virtualisation (VMware ESXi, Microsoft Hyper-V, Nutanix AHV) pour chiffrer les fichiers de disques VM. Utilise des outils d'exfiltration comme FileZilla, RClone, Ngrok.",
            "tags": [
                "actor",
                "theat_actor",
                "ransomware",
                "double_extortion",
                "virtualization",
                "nutanix",
                "linux",
                "rust"
            ],
            "sources": [
                "https://fieldeffect.com/blog/cisa-akira-ransomware-targeting-nutanix-ahv"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "RondoDox botnet",
            "secteur": "Infrastructures et Serveurs (XWiki)",
            "modop": "Exploitation à grande échelle de la vulnérabilité RCE non corrigée (CVE-2025-24893) dans XWiki Platform via injection de code Groovy, pour le déploiement de charges utiles (remote shells, mineurs de crypto-monnaie).",
            "tags": [
                "actor",
                "botnet",
                "exploit",
                "rce",
                "cryptomining"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/rondodox-botnet-malware-now-hacks-servers-using-xwiki-flaw/",
                "https://securityaffairs.com/184702/malware/rondodox-expands-botnet-by-exploiting-xwiki-rce-bug-left-unpatched-since-february-2025.html"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Contagious Interview (Acteurs liés à la Corée du Nord)",
            "secteur": "Développeurs de logiciels, Crypto, Web3",
            "modop": "Campagne d'ingénierie sociale (fausses interviews d'embauche) ciblant les développeurs. Utilisation de projets de code piégés (trojanized code projects) hébergés sur des services légitimes de stockage JSON (JSON Keeper, JSONsilo) pour livrer les infostealers BeaverTail et OtterCookie, ainsi que le RAT InvisibleFerret.",
            "tags": [
                "actor",
                "theat_actor",
                "north_korea",
                "social_engineering",
                "infostealer",
                "supply_chain_abuse"
            ],
            "sources": [
                "https://securityaffairs.com/184726/cyber-warfare-2/north-korean-threat-actors-use-json-sites-to-deliver-malware-via-trojanized-code.html"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Lynx Ransomware",
            "secteur": "Non spécifié (victime non nommée dans l'article détaillé)",
            "modop": "Accès initial via RDP (comptes valides compromis). Mouvement latéral rapide, énumération avec SoftPerfect NetScan et NetExec, création de comptes d'impersonation et installation d'AnyDesk. Exfiltration de données vers temp.sh. Suppression des sauvegardes (Inhibit System Recovery) avant le déploiement du ransomware.",
            "tags": [
                "actor",
                "ransomware",
                "rdp",
                "lateral_movement",
                "data_exfiltration",
                "backup_deletion"
            ],
            "sources": [
                "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Cl0p",
            "secteur": "Médias (The Washington Post), Technologie (Logitech, GlobalLogic), Finance (Allianz UK)",
            "modop": "Campagne d'exploitation de vulnérabilité zero-day dans Oracle E-Business Suite (CVE-2025-61882) pour l'intrusion et le vol de données.",
            "tags": [
                "actor",
                "ransomware",
                "zero_day",
                "data_theft"
            ],
            "sources": [
                "https://research.checkpoint.com/2025/17th-november-threat-intelligence-report/"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Aisuru botnet",
            "secteur": "Fournisseurs de services cloud (Azure), Jeux en ligne",
            "modop": "Lancement d'attaques DDoS massives, y compris la plus grande attaque cloud enregistrée (15,7 Tbps). Botnet basé sur Mirai, utilisant des appareils IoT (routeurs, CCTV/DVR) et des proxies résidentiels pour des attaques multi-vecteurs (UDP floods, HTTPS reflection).",
            "tags": [
                "actor",
                "botnet",
                "ddos",
                "iot",
                "mirai"
            ],
            "sources": [
                "https://securityaffairs.com/184749/cyber-crime/microsoft-mitigated-the-largest-cloud-ddos-ever-recorded-15-7-tbps.html"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Acteurs utilisant l'IA (PROMPTFLUX, APT28/PROMPTSTEAL)",
            "secteur": "Cybercriminalité, Espionnage (APT)",
            "modop": "Utilisation de l'IA (LLMs comme Gemini) pour générer des commandes, réécrire et masquer le code malveillant (malware adaptatif), créer des campagnes de phishing, et automatiser la configuration d'infrastructure d'attaque.",
            "tags": [
                "actor",
                "ai_weaponization",
                "malware_generation",
                "apt",
                "phishing"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        }
    ],
    "Synthèse de l'actualité géopolitique": [
        {
            "secteur": "Gouvernance, Afrique",
            "theme": "Corridor de Lobito",
            "description": "Analyse géopolitique du projet d'infrastructure du Corridor de Lobito (Angola, RDC, Zambie), soutenu par les États-Unis/UE. Le projet, impliquant plus de 10 milliards de dollars, est confronté à des défis structurels majeurs, notamment l'absence d'un organe de coordination formel entre les trois pays ayant des systèmes juridiques différents, ce qui ralentit la mise en œuvre et l'uniformisation des règles.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "afrique",
                "infrastructure",
                "rdc",
                "angola"
            ],
            "sources": [
                "https://www.iris-france.org/geoeconomie-locale-du-corridor-de-lobito-mesurer-limpact-reel-pour-les-acteurs-economiques/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Défense, Asie",
            "theme": "Sécurité de Taiwan",
            "description": "Analyse de la position du Premier ministre japonais Sanae Takaichi, signalant la volonté du Japon de considérer une crise à Taiwan comme une 'situation menaçant la survie', potentiellement déclenchant le droit de légitime défense collective. Cette clarification vise à dissuader la Chine de toute erreur de calcul stratégique.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "japon",
                "taiwan",
                "chine",
                "defense"
            ],
            "sources": [
                "https://www.rusi.org/explore-our-research/publications/commentary/japans-stance-taiwans-security-good-status-quo-and-asian-security"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Sécurité, Afrique de l'Ouest",
            "theme": "Crise au Mali et JNIM",
            "description": "Le Mali est confronté à une dégradation de la sécurité où le Groupe de soutien à l’islam et aux musulmans (JNIM, affilié à Al-Qaïda) contrôle des axes stratégiques autour de Bamako, provoquant une situation de quasi-blocus et le risque d'atomisation du pouvoir. Le régime militaire malien est isolé et s'appuie sur des partenaires russes (Africa Corps).",
            "tags": [
                "geopolitique",
                "geopolitic",
                "mali",
                "jnim",
                "al_qaida",
                "insecurite"
            ],
            "sources": [
                "https://www.iris-france.org/mali-un-monde-seffondre-la-communaute-internationale-regarde-ailleurs/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Droit pénal, Cybercriminalité",
            "theme": "Démantèlement d'infrastructure cybercriminelle",
            "description": "La police néerlandaise a saisi 250 serveurs d'un service d'hébergement 'bulletproof hosting' non nommé (possiblement CrazyRDP), qui était exclusivement utilisé par des cybercriminels et lié à plus de 80 enquêtes depuis 2022. Ce type d'hébergement ignore délibérément les rapports d'abus.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "law_enforcement",
                "bulletproof_hosting",
                "takedown",
                "cybercrime"
            ],
            "sources": [
                "https://securityaffairs.com/184757/cyber-crime/dutch-police-takes-down-bulletproof-hosting-hub-linked-to-80-cybercrime-cases.html"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Éducation, Défense, Russie",
            "theme": "Militarisation de l'éducation en Russie",
            "description": "Expansion du système d'éducation patriotique russe, intégrant profondément le contenu militaire dans les écoles, avec des dépenses fédérales en forte augmentation. L'objectif est la préparation sociale à long terme pour la confrontation géopolitique et une future mobilisation à grande échelle, y compris l'instruction sur les armes et les drones dès l'école primaire.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "russie",
                "militarisation",
                "education"
            ],
            "sources": [
                "https://sploited.blog/2025/11/17/russias-expanding-patriotic-education-system-indicators-of-long-term-mobilization/"
            ],
            "date": "2025-11-18"
        }
    ],
    "Synthèse des violations de données": [
        {
            "secteur": "Secteur public, Administration sociale (France)",
            "victime": "Pajemploi (service de l’Urssaf)",
            "description": "Vol de données survenu le 14 novembre, affectant jusqu'à 1,2 million de salariés. Les données volées comprennent les noms, prénoms, dates et lieux de naissance, adresses postales, numéros de Sécurité sociale et noms d'établissements bancaires. Les numéros de compte, emails et mots de passe n'auraient pas été compromis.",
            "tags": [
                "violation",
                "breach",
                "urssaf",
                "pajemploi",
                "france",
                "ssn",
                "information_disclosure"
            ],
            "sources": [
                "https://www.lemonde.fr/pixels/article/2025/11/17/cybermalveillance-le-service-pajemploi-victime-d-un-vol-de-donnees-jusqu-a-1-2-million-de-personnes-concernees_6653762_4408996.html"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Automobile, Industrie manufacturière",
            "victime": "Jaguar Land Rover (JLR)",
            "description": "Cyberattaque survenue en septembre 2025 (revendiquée par Scattered Lapsus$ Hunters) qui a entraîné l'arrêt de la production et le vol de données. L'incident a coûté 196 millions de livres sterling à l'entreprise pour le trimestre.",
            "tags": [
                "violation",
                "breach",
                "jaguar_land_rover",
                "automobile",
                "ransomware_impact",
                "production_halt"
            ],
            "sources": [
                "https://securityaffairs.com/184742/security/jaguar-land-rover-confirms-major-disruption-and-196m-cost-from-september-cyberattack.html"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Télécommunications, Cloud",
            "victime": "Eurofiber France",
            "description": "Violation de données suite à l'exploitation d'une vulnérabilité dans le système de gestion des tickets. L'acteur ByteToBreach prétend avoir volé des données de 10 000 entreprises clientes, incluant des configurations VPN, des identifiants, du code source, des certificats et des sauvegardes SQL. L'acteur demande une rançon.",
            "tags": [
                "violation",
                "breach",
                "eurofiber",
                "telecom",
                "cloud",
                "extortion",
                "credentials"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/eurofiber-france-warns-of-breach-after-hacker-tries-to-sell-customer-data/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Éducation supérieure",
            "victime": "Princeton University",
            "description": "Compromission d'une base de données le 10 novembre exposant les informations biographiques des anciens élèves, donateurs, professeurs et étudiants (noms, adresses, emails, numéros de téléphone). Les informations financières et mots de passe n'étaient pas stockés dans cette base.",
            "tags": [
                "violation",
                "breach",
                "education",
                "princeton_university",
                "alumni",
                "pii"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/princeton-university-discloses-data-breach-affecting-donors-alumni/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Gouvernement, Tourisme (Somalie)",
            "victime": "Somalia eVisa system",
            "description": "Violation de données exposant 35 417 passeports, y compris ceux de citoyens du Royaume-Uni, des États-Unis et d'Australie. Risque élevé d'exploitation par des groupes terroristes comme Al Shabaab pour l'usurpation d'identité ou les déplacements malveillants.",
            "tags": [
                "violation",
                "breach",
                "somalia",
                "evisa",
                "passport",
                "geopolitic",
                "al_shabaab"
            ],
            "sources": [
                "https://mastodon.social/@Saxafi/115569432645004120"
            ],
            "date": "2025-11-18"
        }
    ],
    "Synthèse des vulnérabilités": [
        {
            "cve_id": "CVE-2025-42890",
            "cvss": "10.0",
            "product": "SAP SQL Anywhere Monitor",
            "description": "Vulnérabilité critique (CVSS 10.0) dans le composant non-GUI due à des identifiants codés en dur, permettant une compromission complète à distance. Recommandation : désactiver le composant affecté.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "sap",
                "rce",
                "hardcoded_credentials",
                "critical"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-60724",
            "cvss": "9.8",
            "product": "Microsoft Graphics Component (GDI+)",
            "description": "Exécution de code à distance (RCE) critique via un dépassement de tampon basé sur le tas (Heap-based buffer overflow). Un attaquant non authentifié peut exploiter cette faille en convainquant une victime d'ouvrir un document malveillant ou en téléchargeant un tel document sur un service web.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "microsoft",
                "rce",
                "heap_overflow"
            ],
            "sources": [
                "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2025/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-24893",
            "cvss": "9.8",
            "product": "XWiki Platform (SolrSearch)",
            "description": "Vulnérabilité d'exécution de code à distance (RCE) critique permettant à des utilisateurs non authentifiés (invités) d'injecter et d'exécuter du code Groovy. Activement exploitée par le botnet RondoDox.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "xwiki",
                "rce",
                "exploit_in_the_wild",
                "rondodox"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/rondodox-botnet-malware-now-hacks-servers-using-xwiki-flaw/",
                "https://securityaffairs.com/184702/malware/rondodox-expands-botnet-by-exploiting-xwiki-rce-bug-left-unpatched-since-february-2025.html"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-42887",
            "cvss": "9.9",
            "product": "SAP Solution Manager",
            "description": "Vulnérabilité critique permettant aux utilisateurs authentifiés d'injecter et d'exécuter du code malveillant sur le système.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "sap",
                "code_injection"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-36251",
            "cvss": "9.6",
            "product": "IBM AIX (service Nimsh)",
            "description": "Vulnérabilité critique d'exécution de commande arbitraire à distance (RCE) sans authentification ni interaction utilisateur, due à un contournement des contrôles de sécurité dans l'implémentation SSL/TLS du service Nimsh.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "ibm",
                "aix",
                "rce",
                "nimsh"
            ],
            "sources": [
                "https://cybersecuritynews.com/ibm-aix-vulnerabilities/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-13223",
            "cvss": "8.8",
            "product": "Google Chrome V8 Engine",
            "description": "Vulnérabilité de confusion de type (Type Confusion) dans le moteur V8, potentiellement exploitée par des attaquants distants via une page HTML malveillante pour provoquer une corruption du tas (heap corruption) et une exécution de code arbitraire (RCE). Faille de type 'zero-day' activement exploitée.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "google_chrome",
                "zero_day",
                "type_confusion",
                "rce",
                "actively_exploited"
            ],
            "sources": [
                "https://thehackernews.com/2025/11/google-issues-security-fix-for-actively.html",
                "https://cybersecuritynews.com/chrome-type-confusion-zero-day/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-8693",
            "cvss": "8.8",
            "product": "Zyxel DX3300-T0 Firmware",
            "description": "Vulnérabilité d'injection de commande (Command Injection) post-authentification dans le paramètre 'priv', permettant à un attaquant authentifié d'exécuter des commandes du système d'exploitation.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "zyxel",
                "command_injection",
                "post_auth"
            ],
            "sources": [
                "https://cvefeed.io/vuln/detail/CVE-2025-8693"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-12974",
            "cvss": "8.1",
            "product": "Gravity Forms (WordPress Plugin)",
            "description": "Téléchargement de fichiers arbitraires non authentifié (unauthenticated arbitrary file upload) via le mécanisme de téléchargement par morceaux hérité. L'absence de validation des types de fichiers permet le téléchargement de fichiers .phar exécutables, pouvant conduire à une exécution de code à distance (RCE).",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "wordpress",
                "rce",
                "file_upload"
            ],
            "sources": [
                "https://cvefeed.io/vuln/detail/CVE-2025-12974"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-30398",
            "cvss": "8.1",
            "product": "Nuance PowerScribe 360 / PowerScribe One",
            "description": "Vulnérabilité de divulgation d'informations critique permettant à des attaquants distants non authentifiés de divulguer des configurations sensibles en exploitant une autorisation manquante via un appel d'API.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "nuance",
                "information_disclosure"
            ],
            "sources": [
                "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2025/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-13023 (et al.)",
            "cvss": "Non spécifié (RCE)",
            "product": "Mozilla Thunderbird",
            "description": "Multiples vulnérabilités, certaines permettant une exécution de code arbitraire à distance (RCE) et un contournement de la politique de sécurité.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "mozilla",
                "thunderbird",
                "rce"
            ],
            "sources": [
                "https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-1016/"
            ],
            "date": "2025-11-18"
        }
    ],
    "Articles": [
        {
            "title": "Akira Ransomware cible désormais Nutanix AHV",
            "description": "Le groupe Akira Ransomware étend ses TTPs pour cibler spécifiquement les infrastructures de virtualisation hyperconvergées (HCI) telles que Nutanix Acropolis Hypervisor (AHV), en plus de VMware ESXi et Microsoft Hyper-V. L'objectif est de chiffrer les fichiers de disques VM et de maximiser l'interruption des opérations. L'accès initial est souvent obtenu via des vulnérabilités dans SonicWall ou Veeam Backup & Replication. La variante Akira_v2, écrite en Rust, améliore la performance et l'évasion, et continue d'utiliser la double extorsion. Le groupe est lié à Storm-1567 et a extorqué plus de 244 millions USD depuis mars 2023.",
            "threat_actor": "Akira Ransomware",
            "indicator_of_compromise": [
                ".akira",
                ".powerranges",
                ".akiranew",
                ".aki"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "Cible stratégique des environnements virtualisés pour paralyser les opérations et accroître le levier d'extorsion, en particulier dans les secteurs de l'IT, de l'éducation et de la finance. La capacité à cibler Nutanix AHV, un composant critique des architectures HCI, représente une menace significative pour les entreprises qui dépendent de cette plateforme.",
            "recommandations": [
                "Mettre en œuvre une segmentation réseau stricte entre l'infrastructure virtuelle et le réseau d'entreprise.",
                "Renforcer la sécurité des systèmes de sauvegarde (gestion des identifiants et isolement des comptes de service).",
                "Appliquer immédiatement les correctifs pour les vulnérabilités SonicWall et Veeam connues utilisées pour l'accès initial."
            ],
            "tags": [
                "ransomware",
                "akira",
                "virtualization",
                "nutanix",
                "ttsp_evolution"
            ],
            "sources": [
                "https://fieldeffect.com/blog/cisa-akira-ransomware-targeting-nutanix-ahv"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Les acteurs de Contagious Interview (Corée du Nord) utilisent des sites JSON pour livrer des malwares via du code piégé",
            "description": "Les acteurs nord-coréens de la campagne 'Contagious Interview', ciblant les développeurs de logiciels (Crypto/Web3), ont mis à jour leurs tactiques. Ils utilisent désormais des services légitimes de stockage JSON (JSON Keeper, JSONsilo, npoint.io) pour héberger et livrer des charges utiles de malwares (BeaverTail infostealer, InvisibleFerret RAT) via des projets de code piégés. Les attaquants se font passer pour des recruteurs, exploitent l'ingénierie sociale et les plateformes de développement pour l'accès initial.",
            "threat_actor": "Contagious Interview (Acteurs liés à la Corée du Nord)",
            "indicator_of_compromise": [
                "pastebin[.]com",
                "npoint[.]io"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "Démontre une sophistication accrue dans l'ingénierie sociale et une dépendance aux services légitimes (Living Off The Cloud) pour la distribution de malwares. Le ciblage des développeurs et de l'écosystème Web3 confirme la motivation financière et l'espionnage technologique de cet acteur.",
            "recommandations": [
                "Sensibiliser les développeurs aux risques des 'projets démo' inattendus lors des processus de recrutement.",
                "Bloquer l'accès aux sites de stockage JSON temporaire depuis les environnements de développement sensibles si non justifié par l'activité métier.",
                "Surveiller l'exécution de scripts ou d'exécutables issus de dépôts externes."
            ],
            "tags": [
                "north_korea",
                "social_engineering",
                "supply_chain",
                "infostealer",
                "malware_delivery"
            ],
            "sources": [
                "https://securityaffairs.com/184726/cyber-warfare-2/north-korean-threat-actors-use-json-sites-to-deliver-malware-via-trojanized-code.html"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Deep Dive : Analyse des TTPs de UNC1549, Outils Personnalisés et Malwares Ciblant l'Écosystème Aérospatiale et Défense",
            "description": "Le groupe d'espionnage UNC1549 (Iran-nexus) cible intensivement les industries de l'Aérospatiale et de la Défense via deux vecteurs principaux : l'exploitation des relations de confiance (tiers/fournisseurs) pour contourner les défenses, et l'hameçonnage ciblé. Le groupe utilise une suite d'outils personnalisés, dont les backdoors TWOSTROKE (C++) et DEEPROOT (Go, Linux), ainsi que des utilitaires de vol d'identifiants comme DCSYNCER.SLICK (attaque DCSync) et CRASHPAD. Les TTPs incluent le détournement de l'ordre de recherche DLL (SOH) pour la persistance, l'abus de services VDI (Citrix/VMWare), et l'utilisation de tunnels SSH inversés pour un Command & Control (C2) furtif. UNC1549 a également signé certains malwares avec des certificats légitimes pour l'évasion.",
            "threat_actor": "UNC1549",
            "indicator_of_compromise": [
                "104.194.215[.]88",
                "13.60.50[.]172",
                "40.119.176[.]233",
                "politicalanorak[.]com",
                "airbus.usa-careers[.]com",
                "mydocs[.]qatarcentral[.]cloudapp[.]azure[.]com",
                "Liste étendue de domaines C2 Azure et IPs"
            ],
            "mitre_ttps": [
                "T1199: Trusted Relationship",
                "T1078: Valid Accounts",
                "T1574.001: DLL Search Order Hijacking",
                "T1003.006: OS Credential Dumping: DCSync",
                "T1113: Screen Capture",
                "T1486: Data Encrypted for Impact (Implicite via outils DCSync)",
                "T1567: Exfiltration Over Web Service (Potentiel)"
            ],
            "analyse": "Rapport critique détaillant la sophistication et les ressources de cet acteur étatique ciblant des informations sensibles et la propriété intellectuelle. L'accent mis sur la chaîne d'approvisionnement et l'abus d'infrastructure cloud légitime (Azure) augmente la difficulté de détection. Le recours aux tunnels SSH inversés et à la signature de code indique une amélioration des capacités opérationnelles pour garantir une persistance à long terme.",
            "recommandations": [
                "Mettre en œuvre des contrôles d'accès stricts pour les fournisseurs tiers (ZTNA, MFA).",
                "Surveiller les connexions RDP et SSH inversées inhabituelles.",
                "Déployer la surveillance de l'ordre de recherche de DLL et bloquer les binaires malveillants signés.",
                "Surveiller l'exécution de DCSync en dehors des processus légitimes de contrôleur de domaine."
            ],
            "tags": [
                "espionnage",
                "apt",
                "iran_nexus",
                "aerospace",
                "defense",
                "supply_chain",
                "custom_malware",
                "persistence",
                "credential_access"
            ],
            "sources": [
                "https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense/"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Le botnet RondoDox exploite une vulnérabilité RCE dans XWiki Platform (CVE-2025-24893)",
            "description": "Le botnet RondoDox exploite activement la faille critique d'exécution de code à distance (RCE) CVE-2025-24893 dans XWiki Platform (SolrSearch) pour infecter des serveurs non corrigés. La vulnérabilité permet l'exécution de code Groovy via une requête HTTP GET, conduisant au téléchargement et à l'exécution d'une charge utile de shell distant ou de mineurs de crypto-monnaie. D'autres acteurs opportunistes ont rapidement adopté cet exploit. La vulnérabilité permet à des utilisateurs non authentifiés d'obtenir le RCE.",
            "threat_actor": "RondoDox botnet",
            "indicator_of_compromise": [
                "74.194.191[.]52 (serveur de charge utile)",
                "172.245.241[.]123",
                "18.228.3[.]224"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "Démontre la rapidité avec laquelle les acteurs de la menace (botnets et mineurs) intègrent les vulnérabilités RCE non corrigées dans leurs campagnes, même plusieurs mois après la publication des correctifs. L'exploitation non authentifiée et facile du RCE XWiki en fait une menace majeure nécessitant une correction immédiate.",
            "recommandations": [
                "Appliquer immédiatement le correctif pour CVE-2025-24893 sur XWiki Platform.",
                "Surveiller le trafic sortant non autorisé vers des ports non standards (pour les reverse shells).",
                "Utiliser des règles de détection (par exemple, YARA/Nuclei) pour identifier les tentatives d'injection de code Groovy via l'endpoint SolrSearch."
            ],
            "tags": [
                "botnet",
                "rce",
                "exploit_in_the_wild",
                "xwiki",
                "cryptomining"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/rondodox-botnet-malware-now-hacks-servers-using-xwiki-flaw/",
                "https://securityaffairs.com/184702/malware/rondodox-expands-botnet-by-exploiting-xwiki-rce-bug-left-unpatched-since-february-2025.html"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Le rançongiciel Lynx : Accès RDP initial, mouvement latéral et chiffrement des sauvegardes",
            "description": "Rapport DFIR détaillant une intrusion de neuf jours par l'acteur Lynx Ransomware. L'accès initial a été obtenu par RDP à l'aide d'identifiants valides pré-compromis (probablement via un courtier en accès initial ou un infostealer). L'acteur a utilisé des outils Living Off The Land (LOLBins), SoftPerfect NetScan et NetExec pour l'énumération du réseau. Le rançongiciel a établi la persistance via la création de faux comptes d'administrateur de domaine et l'installation d'AnyDesk. La phase d'impact a impliqué la suppression des tâches de sauvegarde avant le déploiement du rançongiciel Lynx sur plusieurs serveurs de fichiers et de sauvegarde. L'infrastructure C2 est liée à Railnet LLC/Virtualine (hébergement 'bulletproof').",
            "threat_actor": "Lynx Ransomware",
            "indicator_of_compromise": [
                "195.211.190[.]189",
                "77.90.153[.]30",
                "temp[.]sh",
                "SoftPerfect Network Scanner",
                "NetExec",
                "Hashes de fichiers SHA256/SHA1"
            ],
            "mitre_ttps": [
                "T1078: Valid Accounts (RDP)",
                "T1098: Account Manipulation",
                "T1136: Create Account",
                "T1046: Network Service Scanning",
                "T1567: Exfiltration Over Web Service (temp.sh)",
                "T1490: Inhibit System Recovery (Suppression des sauvegardes)",
                "T1486: Data Encrypted for Impact (Lynx Ransomware)"
            ],
            "analyse": "Illustre la menace persistante des accès RDP mal sécurisés. Les acteurs comme Lynx privilégient l'efficacité et la vitesse, en se concentrant sur les identifiants valides et la destruction des mécanismes de récupération (sauvegardes) avant le chiffrement. L'utilisation de services 'bulletproof hosting' pour l'infrastructure C2 démontre une tentative d'évasion des forces de l'ordre.",
            "recommandations": [
                "Mettre en œuvre l'authentification multifacteur (MFA) pour tous les accès RDP et les comptes à privilèges.",
                "Surveiller l'utilisation d'outils d'administration légitimes (Netscan, NetExec) à partir de postes non standard.",
                "Auditer les journaux pour détecter la création de comptes d'utilisateur 'look-alike' ou non autorisés dans Active Directory.",
                "Isoler les sauvegardes du réseau de production pour empêcher la suppression des tâches (T1490)."
            ],
            "tags": [
                "ransomware",
                "dfir",
                "rdp",
                "persistence",
                "lolbins",
                "credential_access",
                "backup_deletion"
            ],
            "sources": [
                "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Microsoft a atténué la plus grande attaque DDoS jamais enregistrée dans le cloud, 15,7 Tbps",
            "description": "Microsoft Azure DDoS Protection a atténué une attaque DDoS multi-vecteurs massive, atteignant 15,7 Tbps et 3,64 milliards de paquets par seconde (pps), ciblant un point de terminaison unique en Australie. L'attaque est attribuée au botnet Aisuru, basé sur Mirai et utilisant plus de 500 000 adresses IP, principalement des appareils IoT (routeurs, CCTV/DVR) et des proxys résidentiels pour les inondations UDP et les attaques HTTPS.",
            "threat_actor": "Aisuru botnet",
            "indicator_of_compromise": [
                "Plus de 500 000 adresses IP sources"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "L'ampleur de cette attaque (15,7 Tbps) illustre la croissance du potentiel des botnets IoT modernes et des menaces de déni de service distribué (DDoS). L'utilisation d'appareils IoT et de proxies résidentiels permet aux attaquants d'atteindre des niveaux de trafic sans précédent, mettant en évidence la nécessité d'une protection DDoS robuste pour les applications exposées sur Internet.",
            "recommandations": [
                "Assurer une protection DDoS adéquate pour toutes les applications et charges de travail exposées sur Internet, en particulier dans les environnements cloud.",
                "Mettre à jour et sécuriser les appareils IoT pour prévenir leur enrôlement dans des botnets de type Mirai."
            ],
            "tags": [
                "ddos",
                "botnet",
                "azure",
                "cloud_security",
                "iot",
                "aisuru"
            ],
            "sources": [
                "https://securityaffairs.com/184749/cyber-crime/microsoft-mitigated-the-largest-cloud-ddos-ever-recorded-15-7-tbps.html"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Les packages NPM malveillants abusent des redirections Adspect pour échapper à la sécurité",
            "description": "Sept packages malveillants publiés sur le registre Node Package Manager (npm) sous le nom de développeur 'dino_reborn' abusent du service Adspect pour masquer leur nature malveillante. Le mécanisme de 'cloaking' recueille des informations sur l'environnement du navigateur pour séparer les chercheurs des victimes potentielles. Les victimes sont ensuite redirigées vers une fausse page CAPTCHA sur le thème de la crypto-monnaie, déclenchant l'ouverture d'une URL malveillante. Le code intègre des mécanismes anti-analyse (blocage F12, Ctrl+Shift+I).",
            "threat_actor": "dino_reborn",
            "indicator_of_compromise": [
                "geneboo@proton[.]me",
                "toksearches[.]xyz",
                "theonlinesearch[.]com",
                "smartwebfinder[.]com"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "Confirme la persistance des attaques par empoisonnement de la chaîne d'approvisionnement logicielle (supply chain attacks) visant les écosystèmes de développement. L'utilisation d'Adspect, un service légitime de cloaking, et de techniques anti-analyse montre la sophistication croissante des cybercriminels pour échapper aux outils de sécurité automatisés et aux chercheurs.",
            "recommandations": [
                "Examiner l'historique de publication et la réputation des auteurs de packages NPM.",
                "Utiliser des outils d'analyse de dépendances pour détecter les comportements anormaux lors du chargement des packages (exécution immédiate de fonctions IIFE).",
                "Mettre en place une sandboxing stricte lors de l'exécution de nouvelles dépendances."
            ],
            "tags": [
                "supply_chain",
                "npm",
                "malware",
                "cloaking",
                "anti_analysis",
                "info_gathering"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/malicious-npm-packages-abuse-adspect-redirects-to-evade-security/"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Rapport Hebdomadaire : Mise à jour BeeStation, correctifs SAP et l'armement de l'IA par les adversaires",
            "description": "Les acteurs de la menace, y compris les acteurs liés à la Chine et à l'Iran, intensifient l'utilisation de l'Intelligence Artificielle (IA) pour la cybercriminalité et l'espionnage. L'IA est utilisée pour améliorer les malwares (ex: PROMPTFLUX réécrivant son propre code via Gemini) et automatiser des tâches d'attaque (ex: APT28/PROMPTSTEAL utilisant des commandes générées par LLM pour voler des données). La menace de l'IA abaisse la barrière à l'entrée pour les attaquants, permettant des opérations plus adaptatives et évolutives. Ce rapport met également en évidence des vulnérabilités critiques dans Synology BeeStation OS et des failles majeures dans SAP (CVE-2025-42890 CVSS 10.0, CVE-2025-42887 CVSS 9.9).",
            "threat_actor": "PROMPTFLUX, APT28 (PROMPTSTEAL), Acteurs basés en Chine et en Iran",
            "indicator_of_compromise": [
                "Aucun IoC spécifique n'est fourni"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "La prolifération des outils d'IA et des LLMs se traduit par une menace cybernétique accrue et plus adaptative, compliquant la détection des malwares de nouvelle génération. Cela souligne la nécessité de se concentrer sur l'ITDR (Identity Threat Detection and Response) et les défenses contre les vulnérabilités de l'infrastructure critique (SAP, Synology).",
            "recommandations": [
                "Prioriser la mise à jour des systèmes critiques (SAP, Synology) pour corriger les vulnérabilités RCE et d'élévation de privilèges à haut risque.",
                "Déployer des modèles de sécurité basés sur l'identité (ITDR) pour sécuriser les identités humaines et non-humaines, y compris les agents IA.",
                "Former les équipes à identifier les TTPs liés à l'abus d'outils LLM (commandes suspectes, exfiltration de données)."
            ],
            "tags": [
                "ai_weaponization",
                "apt",
                "malware_evolution",
                "sap",
                "critical_vulnerabilities"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Rapport de veille sur les menaces du 17 novembre : La campagne zero-day de Cl0p contre Oracle E-Business Suite s'étend",
            "description": "Le groupe Cl0p poursuit sa campagne exploitant la vulnérabilité zero-day CVE-2025-61882 dans Oracle E-Business Suite. De nouvelles victimes ont été confirmées, notamment The Washington Post, Logitech, Allianz UK et GlobalLogic. Cette campagne vise principalement le vol et l'extorsion de données.",
            "threat_actor": "Cl0p",
            "indicator_of_compromise": [
                "CVE-2025-61882"
            ],
            "mitre_ttps": [
                "Non mentionnées"
            ],
            "analyse": "L'exploitation d'une faille zero-day dans un logiciel d'entreprise aussi répandu qu'Oracle E-Business Suite confère à Cl0p un accès hautement privilégié. Le ciblage de secteurs variés (médias, technologie, finance) montre une recherche opportuniste de grandes victimes et souligne l'impact critique de la campagne d'exploitation de la chaîne d'approvisionnement logicielle.",
            "recommandations": [
                "Mettre en œuvre immédiatement les correctifs d'Oracle E-Business Suite pour CVE-2025-61882.",
                "Surveiller les tentatives d'accès non autorisées aux bases de données Oracle.",
                "Renforcer la détection des activités post-exploitation et d'exfiltration de données massives."
            ],
            "tags": [
                "cl0p",
                "ransomware",
                "zero_day",
                "oracle_ebs",
                "data_theft",
                "supply_chain"
            ],
            "sources": [
                "https://research.checkpoint.com/2025/17th-november-threat-intelligence-report/"
            ],
            "date": "2025-11-18"
        }
    ]
},
"EN": {
    "Analyse transversale": {
        "analyse": "The threat analysis reveals an intensification of sophisticated espionage tactics, notably by the Iran-linked group UNC1549, which exploits trusted relationships (supply chain, third parties) and utilizes custom tools to ensure long-term persistence and high stealth (DCSync, reverse SSH tunnels). Concurrently, the ransomware threat continues to evolve, with the Akira group now focusing on advanced virtualization infrastructures like Nutanix AHV to maximize impact. Exploitation of critical vulnerabilities (RCE in XWiki, SAP, IBM AIX) remains a favored tactic by botnets (RondoDox) and threat actors for initial access. A salient point is the increasing weaponization of Artificial Intelligence (AI) by malicious actors, including APT28 and PROMPTFLUX, to develop adaptive malware and enhance evasion techniques. The news is also marked by several major data breaches affecting government services (Urssaf/Pajemploi in France, eVisa in Somalia) and the private sector (Eurofiber, Jaguar Land Rover), underscoring the criticality of identity data and the direct economic impact of cyberattacks. The general state of threats is characterized by the rapid evolution of TTPs from both state-sponsored actors and cybercriminals, with a focus on weak links in the supply chain and the use of new evasion technologies.",
        "date": "2025-11-18"
    },
    "Synthèse des acteurs malveillants": [
        {
            "nom": "UNC1549 (Iran-nexus)",
            "secteur": "Aerospace, Defense, Aviation, Trusted Third Parties",
            "modop": "Espionage via compromise of trusted relationships (third parties), targeted phishing, DLL Search Order Hijacking (SOH) for custom backdoor execution (TWOSTROKE, DEEPROOT, LIGHTRAIL), DCSync attack, reverse SSH tunnels for C2.",
            "tags": [
                "actor",
                "theat_actor",
                "espionage",
                "iran_nexus",
                "supply_chain",
                "persistence",
                "dll_hijacking",
                "rdp_abuse"
            ],
            "sources": [
                "https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense/"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Akira Ransomware (Storm-1567, Howling Scorpius, Punk Spider, Gold Sahara)",
            "secteur": "Manufacturing, Education, IT, Healthcare, Finance, Agriculture",
            "modop": "Double extortion ransomware attacks. Initial access via SonicWall or Veeam vulnerabilities. Targets virtualization infrastructures (VMware ESXi, Microsoft Hyper-V, Nutanix AHV) to encrypt VM disk files. Uses exfiltration tools like FileZilla, RClone, Ngrok.",
            "tags": [
                "actor",
                "theat_actor",
                "ransomware",
                "double_extortion",
                "virtualization",
                "nutanix",
                "linux",
                "rust"
            ],
            "sources": [
                "https://fieldeffect.com/blog/cisa-akira-ransomware-targeting-nutanix-ahv"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "RondoDox botnet",
            "secteur": "Infrastructure and Servers (XWiki)",
            "modop": "Large-scale exploitation of unpatched RCE vulnerability (CVE-2025-24893) in XWiki Platform via Groovy code injection, deploying payloads (remote shells, cryptocurrency miners).",
            "tags": [
                "actor",
                "botnet",
                "exploit",
                "rce",
                "cryptomining"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/rondodox-botnet-malware-now-hacks-servers-using-xwiki-flaw/",
                "https://securityaffairs.com/184702/malware/rondodox-expands-botnet-by-exploiting-xwiki-rce-bug-left-unpatched-since-february-2025.html"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Contagious Interview (North Korea-linked actors)",
            "secteur": "Software Developers, Crypto, Web3",
            "modop": "Social engineering campaign (fake job interviews) targeting developers. Uses trojanized code projects hosted on legitimate JSON storage services (JSON Keeper, JSONsilo) to deliver BeaverTail and OtterCookie infostealers, and the InvisibleFerret RAT.",
            "tags": [
                "actor",
                "theat_actor",
                "north_korea",
                "social_engineering",
                "infostealer",
                "supply_chain_abuse"
            ],
            "sources": [
                "https://securityaffairs.com/184726/cyber-warfare-2/north-korean-threat-actors-use-json-sites-to-deliver-malware-via-trojanized-code.html"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Lynx Ransomware",
            "secteur": "Unspecified (Unnamed victim in detailed article)",
            "modop": "Initial access via RDP (compromised valid accounts). Rapid lateral movement, enumeration with SoftPerfect NetScan and NetExec, creation of impersonation accounts and AnyDesk installation for persistence. Data exfiltration to temp.sh. Deletion of backups (Inhibit System Recovery) before deploying ransomware.",
            "tags": [
                "actor",
                "ransomware",
                "rdp",
                "lateral_movement",
                "data_exfiltration",
                "backup_deletion"
            ],
            "sources": [
                "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Cl0p",
            "secteur": "Media (The Washington Post), Technology (Logitech, GlobalLogic), Finance (Allianz UK)",
            "modop": "Campaign exploiting a zero-day vulnerability in Oracle E-Business Suite (CVE-2025-61882) for intrusion and data theft.",
            "tags": [
                "actor",
                "ransomware",
                "zero_day",
                "data_theft"
            ],
            "sources": [
                "https://research.checkpoint.com/2025/17th-november-threat-intelligence-report/"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "Aisuru botnet",
            "secteur": "Cloud Service Providers (Azure), Online Gaming",
            "modop": "Launching massive DDoS attacks, including the largest cloud attack ever recorded (15.7 Tbps). Mirai-based botnet, utilizing IoT devices (routers, CCTV/DVRs) and residential proxies for multi-vector attacks (UDP floods, HTTPS reflection).",
            "tags": [
                "actor",
                "botnet",
                "ddos",
                "iot",
                "mirai"
            ],
            "sources": [
                "https://securityaffairs.com/184749/cyber-crime/microsoft-mitigated-the-largest-cloud-ddos-ever-recorded-15-7-tbps.html"
            ],
            "date": "2025-11-18"
        },
        {
            "nom": "AI Users (PROMPTFLUX, APT28/PROMPTSTEAL)",
            "secteur": "Cybercrime, Espionage (APT)",
            "modop": "Using AI (LLMs like Gemini) to generate commands, rewrite and hide malicious code (adaptive malware), create phishing campaigns, and automate attack infrastructure setup.",
            "tags": [
                "actor",
                "ai_weaponization",
                "malware_generation",
                "apt",
                "phishing"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        }
    ],
    "Synthèse de l'actualité géopolitique": [
        {
            "secteur": "Governance, Africa",
            "theme": "Lobito Corridor",
            "description": "Geopolitical analysis of the Lobito Corridor infrastructure project (Angola, DRC, Zambia), backed by the US/EU. The project, involving over $10 billion, faces major structural challenges, particularly the lack of a formal coordination body among the three countries with different legal systems, which slows implementation and rule standardization.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "africa",
                "infrastructure",
                "drc",
                "angola"
            ],
            "sources": [
                "https://www.iris-france.org/geoeconomie-locale-du-corridor-de-lobito-mesurer-limpact-reel-pour-les-acteurs-economiques/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Defense, Asia",
            "theme": "Taiwan Security",
            "description": "Analysis of Japanese Prime Minister Sanae Takaichi's stance, signaling Japan's readiness to consider a Taiwan contingency as a 'survival threatening situation,' potentially triggering the right to collective self-defense. This clarification aims to deter China from strategic miscalculation.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "japan",
                "taiwan",
                "china",
                "defense"
            ],
            "sources": [
                "https://www.rusi.org/explore-our-research/publications/commentary/japans-stance-taiwans-security-good-status-quo-and-asian-security"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Security, West Africa",
            "theme": "Mali Crisis and JNIM",
            "description": "Mali is experiencing deteriorating security where the Group for the Support of Islam and Muslims (JNIM, affiliated with Al-Qaeda) controls strategic axes around Bamako, causing a quasi-blockade situation and the risk of state atomization. The Malian military regime is isolated and relies on Russian partners (Africa Corps).",
            "tags": [
                "geopolitique",
                "geopolitic",
                "mali",
                "jnim",
                "al_qaeda",
                "insecurity"
            ],
            "sources": [
                "https://www.iris-france.org/mali-un-monde-seffondre-la-communaute-internationale-regarde-ailleurs/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Law Enforcement, Cybercrime",
            "theme": "Cybercriminal Infrastructure Takedown",
            "description": "Dutch police seized 250 servers belonging to an unnamed 'bulletproof hosting' service (possibly CrazyRDP) exclusively used by cybercriminals and linked to over 80 investigations since 2022. This type of hosting deliberately ignores abuse reports.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "law_enforcement",
                "bulletproof_hosting",
                "takedown",
                "cybercrime"
            ],
            "sources": [
                "https://securityaffairs.com/184757/cyber-crime/dutch-police-takes-down-bulletproof-hosting-hub-linked-to-80-cybercrime-cases.html"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Education, Defense, Russia",
            "theme": "Militarization of Russian Education",
            "description": "Expansion of Russia's patriotic education system, deeply integrating military content into schools, with sharply increasing federal spending. The goal is long-term social preparation for geopolitical confrontation and future large-scale mobilization, including instruction on weapons and drones starting in primary school.",
            "tags": [
                "geopolitique",
                "geopolitic",
                "russia",
                "militarization",
                "education"
            ],
            "sources": [
                "https://sploited.blog/2025/11/17/russias-expanding-patriotic-education-system-indicators-of-long-term-mobilization/"
            ],
            "date": "2025-11-18"
        }
    ],
    "Synthèse des violations de données": [
        {
            "secteur": "Public Sector, Social Administration (France)",
            "victime": "Pajemploi (Urssaf service)",
            "description": "Data theft occurred on November 14, affecting up to 1.2 million employees. Stolen data includes names, dates and places of birth, postal addresses, Social Security numbers (SSN), and banking establishment names. Account numbers, emails, and passwords were reportedly not compromised.",
            "tags": [
                "violation",
                "breach",
                "urssaf",
                "pajemploi",
                "france",
                "ssn",
                "information_disclosure"
            ],
            "sources": [
                "https://www.lemonde.fr/pixels/article/2025/11/17/cybermalveillance-le-service-pajemploi-victime-d-un-vol-de-donnees-jusqu-a-1-2-million-de-personnes-concernees_6653762_4408996.html"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Automotive, Manufacturing Industry",
            "victime": "Jaguar Land Rover (JLR)",
            "description": "Cyberattack in September 2025 (claimed by Scattered Lapsus$ Hunters) resulted in production halts and data theft. The incident cost the company £196 million in the quarter.",
            "tags": [
                "violation",
                "breach",
                "jaguar_land_rover",
                "automotive",
                "ransomware_impact",
                "production_halt"
            ],
            "sources": [
                "https://securityaffairs.com/184742/security/jaguar-land-rover-confirms-major-disruption-and-196m-cost-from-september-cyberattack.html"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Telecommunications, Cloud",
            "victime": "Eurofiber France",
            "description": "Data breach resulting from the exploitation of a vulnerability in the ticket management system. Actor ByteToBreach claims to have stolen data from 10,000 corporate clients, including VPN configurations, credentials, source code, certificates, and SQL backups. The actor demanded a ransom payment.",
            "tags": [
                "violation",
                "breach",
                "eurofiber",
                "telecom",
                "cloud",
                "extortion",
                "credentials"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/eurofiber-france-warns-of-breach-after-hacker-tries-to-sell-customer-data/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Higher Education",
            "victime": "Princeton University",
            "description": "Compromise of a database on November 10, exposing biographical information of alumni, donors, faculty, and students (names, addresses, emails, phone numbers). Financial information and passwords were not stored in this database.",
            "tags": [
                "violation",
                "breach",
                "education",
                "princeton_university",
                "alumni",
                "pii"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/princeton-university-discloses-data-breach-affecting-donors-alumni/"
            ],
            "date": "2025-11-18"
        },
        {
            "secteur": "Government, Tourism (Somalia)",
            "victime": "Somalia eVisa system",
            "description": "Data breach exposing 35,417 passports, including those of UK, US, and Australian citizens. High risk of exploitation by terrorist groups like Al Shabaab for identity theft or malicious travel.",
            "tags": [
                "violation",
                "breach",
                "somalia",
                "evisa",
                "passport",
                "geopolitic",
                "al_shabaab"
            ],
            "sources": [
                "https://mastodon.social/@Saxafi/115569432645004120"
            ],
            "date": "2025-11-18"
        }
    ],
    "Synthèse des vulnérabilités": [
        {
            "cve_id": "CVE-2025-42890",
            "cvss": "10.0",
            "product": "SAP SQL Anywhere Monitor",
            "description": "Critical vulnerability (CVSS 10.0) in the non-GUI component due to hardcoded credentials, enabling full remote compromise. Recommendation: discontinue the affected monitor component.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "sap",
                "rce",
                "hardcoded_credentials",
                "critical"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-60724",
            "cvss": "9.8",
            "product": "Microsoft Graphics Component (GDI+)",
            "description": "Critical Remote Code Execution (RCE) via a heap-based buffer overflow. An unauthenticated attacker can exploit this by convincing a victim to open a specially crafted document or by uploading such a document to a web service.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "microsoft",
                "rce",
                "heap_overflow"
            ],
            "sources": [
                "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2025/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-24893",
            "cvss": "9.8",
            "product": "XWiki Platform (SolrSearch)",
            "description": "Critical Remote Code Execution (RCE) vulnerability allowing unauthenticated users (guests) to inject and execute Groovy code. Actively exploited by the RondoDox botnet.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "xwiki",
                "rce",
                "exploit_in_the_wild",
                "rondodox"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/rondodox-botnet-malware-now-hacks-servers-using-xwiki-flaw/",
                "https://securityaffairs.com/184702/malware/rondodox-expands-botnet-by-exploiting-xwiki-rce-bug-left-unpatched-since-february-2025.html"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-42887",
            "cvss": "9.9",
            "product": "SAP Solution Manager",
            "description": "Critical vulnerability allowing authenticated users to inject and run malicious code on the system.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "sap",
                "code_injection"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-36251",
            "cvss": "9.6",
            "product": "IBM AIX (Nimsh service)",
            "description": "Critical Remote Code Execution (RCE) vulnerability without authentication or user interaction, due to a security control bypass in the Nimsh service’s SSL/TLS implementation.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "ibm",
                "aix",
                "rce",
                "nimsh"
            ],
            "sources": [
                "https://cybersecuritynews.com/ibm-aix-vulnerabilities/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-13223",
            "cvss": "8.8",
            "product": "Google Chrome V8 Engine",
            "description": "Type Confusion vulnerability in the V8 engine, potentially exploited by remote attackers via a crafted HTML page to cause heap corruption and arbitrary code execution (RCE). An actively exploited 'zero-day' flaw.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "google_chrome",
                "zero_day",
                "type_confusion",
                "rce",
                "actively_exploited"
            ],
            "sources": [
                "https://thehackernews.com/2025/11/google-issues-security-fix-for-actively.html",
                "https://cybersecuritynews.com/chrome-type-confusion-zero-day/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-8693",
            "cvss": "8.8",
            "product": "Zyxel DX3300-T0 Firmware",
            "description": "Post-authentication Command Injection vulnerability in the 'priv' parameter, allowing an authenticated attacker to execute operating system (OS) commands.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "zyxel",
                "command_injection",
                "post_auth"
            ],
            "sources": [
                "https://cvefeed.io/vuln/detail/CVE-2025-8693"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-12974",
            "cvss": "8.1",
            "product": "Gravity Forms (WordPress Plugin)",
            "description": "Unauthenticated arbitrary file upload via the legacy chunked upload mechanism. The lack of file type validation allows uploading executable .phar files, potentially leading to Remote Code Execution (RCE).",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "wordpress",
                "rce",
                "file_upload"
            ],
            "sources": [
                "https://cvefeed.io/vuln/detail/CVE-2025-12974"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-30398",
            "cvss": "8.1",
            "product": "Nuance PowerScribe 360 / PowerScribe One",
            "description": "Critical information disclosure vulnerability allowing unauthenticated remote attackers to reveal sensitive configuration settings by exploiting missing authorization via an API call.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "nuance",
                "information_disclosure"
            ],
            "sources": [
                "https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2025/"
            ],
            "date": "2025-11-18"
        },
        {
            "cve_id": "CVE-2025-13023 (et al.)",
            "cvss": "Unspecified (RCE)",
            "product": "Mozilla Thunderbird",
            "description": "Multiple vulnerabilities, some allowing remote arbitrary code execution (RCE) and security policy bypass.",
            "tags": [
                "vulnerabilité",
                "vulnerability",
                "mozilla",
                "thunderbird",
                "rce"
            ],
            "sources": [
                "https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-1016/"
            ],
            "date": "2025-11-18"
        }
    ],
    "Articles": [
        {
            "title": "Akira Ransomware Targeting Nutanix AHV",
            "description": "The Akira Ransomware group is expanding its TTPs to specifically target hyper-converged virtualization infrastructure (HCI) such as Nutanix Acropolis Hypervisor (AHV), in addition to VMware ESXi and Microsoft Hyper-V. The goal is to encrypt VM disk files and maximize operational disruption. Initial access is often achieved via vulnerabilities in SonicWall or Veeam Backup & Replication. The Akira_v2 variant, written in Rust, improves performance and evasion and continues to use double extortion. The group is linked to Storm-1567 and has extorted over $244 million since March 2023.",
            "threat_actor": "Akira Ransomware",
            "indicator_of_compromise": [
                ".akira",
                ".powerranges",
                ".akiranew",
                ".aki"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "Strategic targeting of virtual environments to paralyze operations and increase extortion leverage, especially across the IT, education, and finance sectors. The capability to target Nutanix AHV, a critical component of HCI architectures, represents a significant threat to enterprises relying on this platform.",
            "recommandations": [
                "Implement strict network segmentation between virtual infrastructure and the corporate network.",
                "Strengthen backup system security (credential management and service account isolation).",
                "Immediately patch known SonicWall and Veeam vulnerabilities used for initial access."
            ],
            "tags": [
                "ransomware",
                "akira",
                "virtualization",
                "nutanix",
                "ttsp_evolution"
            ],
            "sources": [
                "https://fieldeffect.com/blog/cisa-akira-ransomware-targeting-nutanix-ahv"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Malicious NPM packages abuse Adspect redirects to evade security",
            "description": "Seven malicious packages published on the Node Package Manager (npm) registry under the developer name 'dino_reborn' abuse the Adspect service to cloak their malicious nature. The cloaking mechanism collects browser environment information to separate researchers from potential victims. Victims are then redirected to a fake cryptocurrency-themed CAPTCHA page, triggering the opening of a malicious URL. The code includes anti-analysis mechanisms (blocking F12, Ctrl+Shift+I).",
            "threat_actor": "dino_reborn",
            "indicator_of_compromise": [
                "geneboo@proton[.]me",
                "toksearches[.]xyz",
                "theonlinesearch[.]com",
                "smartwebfinder[.]com"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "Confirms the persistence of supply chain poisoning attacks targeting development ecosystems. The use of Adspect, a legitimate cloaking service, and anti-analysis techniques demonstrates the increasing sophistication of cybercriminals to evade automated security tools and researchers.",
            "recommandations": [
                "Examine the publication history and reputation of NPM package authors.",
                "Use dependency analysis tools to detect abnormal behavior during package loading (Immediate Invoked Function Expression execution).",
                "Implement strict sandboxing when executing new dependencies."
            ],
            "tags": [
                "supply_chain",
                "npm",
                "malware",
                "cloaking",
                "anti_analysis",
                "info_gathering"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/malicious-npm-packages-abuse-adspect-redirects-to-evade-security/"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Microsoft mitigated the largest cloud DDoS ever recorded, 15.7 Tbps",
            "description": "Microsoft Azure DDoS Protection mitigated a massive multi-vector DDoS attack, peaking at 15.7 Tbps and 3.64 billion packets per second (pps), targeting a single endpoint in Australia. The attack is attributed to the Aisuru botnet, based on Mirai, using over 500,000 IP addresses, mainly IoT devices (routers, CCTV/DVRs) and residential proxies for UDP floods and HTTPS attacks.",
            "threat_actor": "Aisuru botnet",
            "indicator_of_compromise": [
                "Over 500,000 source IP addresses"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "The scale of this attack (15.7 Tbps) illustrates the growing potential of modern IoT botnets and Distributed Denial of Service (DDoS) threats. The use of IoT devices and residential proxies allows attackers to achieve unprecedented traffic levels, highlighting the necessity for robust DDoS protection for internet-exposed applications.",
            "recommandations": [
                "Ensure adequate DDoS protection for all internet-facing applications and workloads, especially in cloud environments.",
                "Update and secure IoT devices to prevent their enrollment into Mirai-type botnets."
            ],
            "tags": [
                "ddos",
                "botnet",
                "azure",
                "cloud_security",
                "iot",
                "aisuru"
            ],
            "sources": [
                "https://securityaffairs.com/184749/cyber-crime/microsoft-mitigated-the-largest-cloud-ddos-ever-recorded-15-7-tbps.html"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "North Korean threat actors use JSON sites to deliver malware via trojanized code",
            "description": "North Korean actors behind the 'Contagious Interview' campaign, targeting software developers (Crypto/Web3), have updated their tactics. They now use legitimate JSON storage services (JSON Keeper, JSONsilo, npoint.io) to host and deliver malware payloads (BeaverTail infostealer, InvisibleFerret RAT) via trojanized code projects. Attackers pose as recruiters, leveraging social engineering and development platforms for initial access.",
            "threat_actor": "Contagious Interview (North Korea-linked actors)",
            "indicator_of_compromise": [
                "pastebin[.]com",
                "npoint[.]io"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "Demonstrates increased sophistication in social engineering and reliance on legitimate services (Living Off The Cloud) for malware distribution. Targeting developers and the Web3 ecosystem confirms the financial and technological espionage motivation of this actor.",
            "recommandations": [
                "Educate developers on the risks of unexpected 'demo projects' during recruitment processes.",
                "Block access to temporary JSON storage sites from sensitive development environments if not business-justified.",
                "Monitor for the execution of scripts or executables sourced from external repositories."
            ],
            "tags": [
                "north_korea",
                "social_engineering",
                "supply_chain",
                "infostealer",
                "malware_delivery"
            ],
            "sources": [
                "https://securityaffairs.com/184726/cyber-warfare-2/north-korean-threat-actors-use-json-sites-to-deliver-malware-via-trojanized-code.html"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "RondoDox botnet malware now hacks servers using XWiki flaw",
            "description": "The RondoDox botnet is actively exploiting the critical Remote Code Execution (RCE) flaw CVE-2025-24893 in XWiki Platform (SolrSearch) to infect unpatched servers. The vulnerability allows Groovy code execution via a specially crafted HTTP GET request, leading to the download and execution of a remote shell payload or cryptocurrency miners. Other opportunistic actors have quickly adopted this exploit. The vulnerability allows unauthenticated users to achieve RCE.",
            "threat_actor": "RondoDox botnet",
            "indicator_of_compromise": [
                "74.194.191[.]52 (Payload server)",
                "172.245.241[.]123",
                "18.228.3[.]224"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "Demonstrates the speed with which threat actors (botnets and miners) integrate unpatched RCE vulnerabilities into their campaigns, even months after patches are released. The unauthenticated and easy exploitation of the XWiki RCE makes it a major threat requiring immediate remediation.",
            "recommandations": [
                "Immediately apply the patch for CVE-2025-24893 on XWiki Platform.",
                "Monitor unauthorized outbound traffic to non-standard ports (for reverse shells).",
                "Use detection rules (e.g., YARA/Nuclei) to identify Groovy code injection attempts via the SolrSearch endpoint."
            ],
            "tags": [
                "botnet",
                "rce",
                "exploit_in_the_wild",
                "xwiki",
                "cryptomining"
            ],
            "sources": [
                "https://www.bleepingcomputer.com/news/security/rondodox-botnet-malware-now-hacks-servers-using-xwiki-flaw/",
                "https://securityaffairs.com/184702/malware/rondodox-expands-botnet-by-exploiting-xwiki-rce-bug-left-unpatched-since-february-2025.html"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Threat Intelligence Report: November 17th – Cl0p's Oracle E-Business Suite zero-day campaign expands",
            "description": "The Cl0p group is continuing its campaign exploiting the zero-day vulnerability CVE-2025-61882 in Oracle E-Business Suite. New victims confirmed include The Washington Post, Logitech, Allianz UK, and GlobalLogic. This campaign primarily targets data theft and extortion.",
            "threat_actor": "Cl0p",
            "indicator_of_compromise": [
                "CVE-2025-61882"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "Exploiting a zero-day flaw in widely used enterprise software like Oracle E-Business Suite grants Cl0p highly privileged access. The targeting of varied sectors (media, technology, finance) shows an opportunistic search for large victims and highlights the critical impact of the software supply chain exploitation campaign.",
            "recommandations": [
                "Immediately implement Oracle E-Business Suite patches for CVE-2025-61882.",
                "Monitor unauthorized access attempts to Oracle databases.",
                "Enhance detection of post-exploitation activities and massive data exfiltration."
            ],
            "tags": [
                "cl0p",
                "ransomware",
                "zero_day",
                "oracle_ebs",
                "data_theft",
                "supply_chain"
            ],
            "sources": [
                "https://research.checkpoint.com/2025/17th-november-threat-intelligence-report/"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Weekly Threat Intel: BeeStation Updates, SAP Patch Releases, Google AI Weaponization & More",
            "description": "Threat actors, including China and Iran-linked groups, are intensifying the use of Artificial Intelligence (AI) for cybercrime and espionage. AI is used to enhance malware (e.g., PROMPTFLUX rewriting its own code via Gemini) and automate attack tasks (e.g., APT28/PROMPTSTEAL using LLM-generated commands for data theft). The AI threat lowers the barrier to entry for attackers, enabling more adaptive and scalable operations. This report also highlights critical vulnerabilities in Synology BeeStation OS and major SAP flaws (CVE-2025-42890 CVSS 10.0, CVE-2025-42887 CVSS 9.9).",
            "threat_actor": "PROMPTFLUX, APT28 (PROMPTSTEAL), China and Iran-based actors",
            "indicator_of_compromise": [
                "No specific IoC provided"
            ],
            "mitre_ttps": [
                "Not mentioned"
            ],
            "analyse": "The proliferation of AI tools and LLMs translates into a heightened and more adaptive cyber threat, complicating the detection of next-generation malware. This underscores the need to focus on ITDR (Identity Threat Detection and Response) and critical infrastructure vulnerability defenses (SAP, Synology).",
            "recommandations": [
                "Prioritize updating critical systems (SAP, Synology) to patch high-risk RCE and elevation of privilege vulnerabilities.",
                "Deploy Identity Threat Detection and Response (ITDR) models to secure human and non-human identities, including AI agents.",
                "Train teams to identify TTPs related to LLM tool abuse (suspicious commands, data exfiltration)."
            ],
            "tags": [
                "ai_weaponization",
                "apt",
                "malware_evolution",
                "sap",
                "critical_vulnerabilities"
            ],
            "sources": [
                "https://fieldeffect.com/blog/weekly-threat-intel-newsletter-2025-11-17"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Frontline Intelligence: Analysis of UNC1549 TTPs, Custom Tools, and Malware Targeting the Aerospace and Defense Ecosystem",
            "description": "The UNC1549 espionage group (Iran-nexus) intensively targets the Aerospace and Defense industries through two main vectors: exploiting trusted relationships (third parties/suppliers) to bypass defenses, and targeted spear-phishing. The group uses a suite of custom tools, including the TWOSTROKE (C++) and DEEPROOT (Go, Linux) backdoors, along with credential theft utilities like DCSYNCER.SLICK (DCSync attack) and CRASHPAD. TTPs include DLL Search Order Hijacking (SOH) for persistence, abuse of VDI services (Citrix/VMWare), and the use of reverse SSH tunnels for stealthy Command & Control (C2). UNC1549 also signed some malware with legitimate certificates for evasion.",
            "threat_actor": "UNC1549",
            "indicator_of_compromise": [
                "104.194.215[.]88",
                "13.60.50[.]172",
                "40.119.176[.]233",
                "politicalanorak[.]com",
                "airbus.usa-careers[.]com",
                "mydocs[.]qatarcentral[.]cloudapp[.]azure[.]com",
                "Extended list of Azure C2 domains and IPs"
            ],
            "mitre_ttps": [
                "T1199: Trusted Relationship",
                "T1078: Valid Accounts",
                "T1574.001: DLL Search Order Hijacking",
                "T1003.006: OS Credential Dumping: DCSync",
                "T1113: Screen Capture",
                "T1486: Data Encrypted for Impact (Implied via DCSync tools)",
                "T1567: Exfiltration Over Web Service (Potential)"
            ],
            "analyse": "Critical report detailing the sophistication and resources of this state actor targeting sensitive information and intellectual property. The focus on the supply chain and abuse of legitimate cloud infrastructure (Azure) increases detection difficulty. The use of reverse SSH tunnels and code signing indicates improved operational security for long-term persistence.",
            "recommandations": [
                "Implement strict access controls for third-party vendors (ZTNA, MFA).",
                "Monitor for unusual RDP and reverse SSH connections.",
                "Deploy monitoring for DLL search order abuse and block signed malicious binaries.",
                "Monitor DCSync execution outside of legitimate domain controller processes."
            ],
            "tags": [
                "espionage",
                "apt",
                "iran_nexus",
                "aerospace",
                "defense",
                "supply_chain",
                "custom_malware",
                "persistence",
                "credential_access"
            ],
            "sources": [
                "https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense/"
            ],
            "date": "2025-11-18"
        },
        {
            "title": "Cat’s Got Your Files: Lynx Ransomware",
            "description": "DFIR report detailing a nine-day intrusion by the Lynx Ransomware actor. Initial access was gained via RDP using pre-compromised valid credentials (likely from an initial access broker or infostealer). The actor used Living Off The Land Binaries (LOLBins), SoftPerfect NetScan, and NetExec for network enumeration. Persistence was established via creating 'look-alike' domain admin accounts and installing AnyDesk. The impact phase involved deleting backup jobs before deploying Lynx ransomware across multiple file and backup servers. The C2 infrastructure is linked to Railnet LLC/Virtualine (bulletproof hosting).",
            "threat_actor": "Lynx Ransomware",
            "indicator_of_compromise": [
                "195.211.190[.]189",
                "77.90.153[.]30",
                "temp[.]sh",
                "SoftPerfect Network Scanner",
                "NetExec",
                "SHA256/SHA1 file hashes"
            ],
            "mitre_ttps": [
                "T1078: Valid Accounts (RDP)",
                "T1098: Account Manipulation",
                "T1136: Create Account",
                "T1046: Network Service Scanning",
                "T1567: Exfiltration Over Web Service (temp.sh)",
                "T1490: Inhibit System Recovery (Backup Deletion)",
                "T1486: Data Encrypted for Impact (Lynx Ransomware)"
            ],
            "analyse": "Illustrates the persistent threat posed by poorly secured RDP access. Actors like Lynx prioritize efficiency and speed, focusing on valid credentials and destroying recovery mechanisms (backups) before encryption. The use of bulletproof hosting services for C2 infrastructure demonstrates an attempt to evade law enforcement.",
            "recommandations": [
                "Implement Multi-Factor Authentication (MFA) for all RDP access and privileged accounts.",
                "Monitor the use of legitimate administrative tools (Netscan, NetExec) from non-standard endpoints.",
                "Audit logs for the creation of unauthorized or 'look-alike' user accounts in Active Directory.",
                "Isolate backups from the production network to prevent job deletion (T1490)."
            ],
            "tags": [
                "ransomware",
                "dfir",
                "rdp",
                "persistence",
                "lolbins",
                "credential_access",
                "backup_deletion"
            ],
            "sources": [
                "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/"
            ],
            "date": "2025-11-18"
        }
    ]
}
}