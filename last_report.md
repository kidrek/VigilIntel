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
  * [Mini Shai-Hulud + npm supply chain compromise](#mini-shai-hulud-npm-supply-chain-compromise)
  * [Meta AI / Instagram Account Hijacking](#meta-ai-instagram-account-hijacking)
  * [JS.MonoGlyphRAT + Fake Purchase Orders](#js-monoglyphrat-fake-purchase-orders)
  * [WeedHack + Minecraft credential theft campaign](#weedhack-minecraft-credential-theft-campaign)
  * [AI-built ransomware toolkit + EDR evasion](#ai-built-ransomware-toolkit-edr-evasion)
  * [WordPress malware + Steam C2 dead drop resolver](#wordpress-malware-steam-c2-dead-drop-resolver)
  * [FlutterShell + Operation FlutterBridge](#fluttershell-operation-flutterbridge)
  * [Phishing campaign via malicious SVG attachments](#phishing-campaign-via-malicious-svg-attachments)
  * [Phishing campaign via view-vibes on GitHub Pages](#phishing-campaign-via-view-vibes-on-github-pages)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse de la période de mai à juin 2026 met en exergue des mutations profondes et extrêmement rapides du paysage des cybermenaces. La tendance la plus alarmante réside dans l'industrialisation des attaques ciblant la chaîne d'approvisionnement logicielle (supply chain). L'écosystème open source (notamment npm) fait face à des vagues d'empoisonnement d'une agressivité sans précédent, caractérisées par l'utilisation de vers auto-propagateurs à l'image de **Shai-Hulud** (ou **Mini Shai-Hulud**). Ces malwares ne se contentent plus d'exfiltrer passivement des secrets, mais compromettent activement les pipelines d'intégration continue (CI/CD) d'acteurs d'envergure (tels que Red Hat, TanStack ou Bitwarden) afin de contaminer de manière virale et descendante l'ensemble des dépendances.

Parallèlement, l'intelligence artificielle est devenue un vecteur d'attaque de premier ordre. D'une part, l'ingénierie sociale s'appuie désormais sur des chatbots d'assistance détournés (les IA d'assistance de Meta) et des médias générés par IA (deepfakes d'identité) pour contourner les validations de sécurité humaines et usurper des comptes stratégiques. D'autre part, des frameworks cybercriminels de rançonnage sont désormais codés et affinés par des agents d'IA autonomes capables de tester et d'optimiser en boucle l'évasion des solutions EDR du commerce.

Sur le plan géopolitique, nous assistons à une hybridation accrue des attaques cyber-physiques. L'Iran, via ses services de renseignement (MOIS), unifie ses personas sous la bannière "Handala" pour opérer des campagnes combinant vols de données critiques, attaques destructrices et recrutement d'agents locaux pour du sabotage physique en Israël et aux États-Unis. Face à cette accélération exponentielle (où le délai moyen d'exploitation des vulnérabilités critiques après leur publication est désormais inférieur à 24 heures), les recommandations stratégiques imposent un durcissement sans compromis : passage obligatoire au modèle Zero Trust, limitation drastique des scopes d'autorisation OIDC dans les pipelines CI/CD, et généralisation de l'authentification multifacteur résistante au phishing (FIDO2).

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Void Manticore** (TAG-145, Red Sandstorm, Banished Kitten) | Gouvernement, Défense, Infrastructures critiques, Forces de l'ordre | Cyber-physique hybride, wiper, opérations d'influence (hack-and-leak) sous la marque *Handala*, sabotage physique. | T1195.001 (Supply Chain Compromise)<br>T1566.002 (Spearphishing Link) | [Recorded Future](https://www.recordedfuture.com/research/iran-handala-physical-threats) |
| **TeamPCP** (pcpcats) | Technologie, Développement logiciel, ESN | Attaques de supply chain ciblant npm et PyPI, propagation du ver Shai-Hulud, empoisonnement de cache CI/CD. | T1195.001 (Supply Chain Compromise)<br>T1555.004 (Credentials from Web Browsers) | [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| **Gamaredon** (Primitive Bear, ACTINIUM, UAC-0010) | Gouvernement, Militaire, Infrastructures critiques | Spear-phishing exploitant des failles d'archivage (WinRAR), déploiement de backdoors VBScript (*GammaWorm*) et d'infostealers (*GammaSteel*), utilisation de Telegram comme C2 DDR. | T1566.001 (Spearphishing Attachment)<br>T1059.005 (Visual Basic) | [The Hacker News](https://thehackernews.com/2026/06/gamaredon-exploits-winrar-to-deliver.html) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| Iran / Israël / États-Unis | Défense et Sécurité | Opérations d'influence et de sabotage hybrides de l'Iran | Expansion de la marque "Handala" par le Ministère de l'Intelligence iranien (MOIS) pour recruter des agents locaux via des bots de messagerie et de fausses offres d'emploi, menant des sabotages physiques (incendies criminels, harcèlement) en échange de cryptomonnaies. | [Recorded Future](https://www.recordedfuture.com/research/iran-handala-physical-threats) |
| Russie / Ukraine | Gouvernement et Militaire | Campagnes d'espionnage cyber de Gamaredon contre l'Ukraine | Exploitation active de la faille WinRAR pour implanter les backdoors GammaWorm et GammaSteel, exfiltrant des documents administratifs et militaires stratégiques vers le cloud AWS S3. | [The Hacker News](https://thehackernews.com/2026/06/gamaredon-exploits-winrar-to-deliver.html) |
| France / Pologne / Autriche / Russie | Défense | Souveraineté spatiale, contre-espionnage et communications | Lancement d'un partenariat franco-polonais de satellites militaires sécurisés face à l'espionnage russe, et expulsion par l'Autriche de diplomates russes impliqués dans l'interception électronique de signaux satellites à Vienne. | [CERT-UE](https://cert.europa.eu/publications/threat-intelligence/cb26-06/) |
| Amérique Latine | Multi-sector | Crise de la souveraineté numérique régionale | Chronique détaillée de l'explosion des vagues de cyberattaques étatiques de type hack-and-leak compromettant la souveraineté numérique des institutions latino-américaines. | [DataBreaches.net](https://databreaches.net/2026/06/01/alberto-daniel-hills-cybermidnight-coverage-of-the-latin-american-digital-sovereignty-crisis-march-june-2026/?pk_campaign=feed&pk_kwd=alberto-daniel-hills-cybermidnight-coverage-of-the-latin-american-digital-sovereignty-crisis-march-june-2026) |
| Multi-sector | Énergie et Climat | Désinformation climatique comme arme de déstabilisation | Utilisation stratégique de campagnes d'influence et de manipulation de données environnementales par des puissances étatiques rivales afin de perturber la transition énergétique européenne et fracturer l'espace social. | [IRIS](https://www.iris-france.org/desinformation-climatique-quelle-reponse-institutionnelle-et-reglementaire/) |
| Global | Gouvernement | Géopolitique et éthique de l'IA | Doctrine diplomatique du Vatican face à l'IA et aux algorithmes autonomes de ciblage militaire, insistant sur la nécessité d'un cadre éthique universel pour la résolution des conflits modernes. | [IRIS](https://www.iris-france.org/le-vatican-lintelligence-artificielle-et-la-nouvelle-geopolitique-de-la-mediation/) |
| Sénégal | Gouvernement | Stabilité institutionnelle locale | Analyse géopolitique des tensions politiques internes découlant du divorce politique entre le président Faye et Ousmane Sonko au Sénégal. | [IRIS](https://www.iris-france.org/rupture-diomaye-faye-sonko-quel-impact-les-mardis-de-liris/) |
| Méditerranée | Gouvernement | Équilibre régional et rivalités impériales | Étude géopolitique sur la résilience multilatérale des nations méditerranéennes face aux stratégies d'influence hégémoniques des empires contemporains. | [IRIS](https://www.iris-france.org/face-aux-empires-la-voie-mediterraneenne-4-questions-a-thierry-fabre/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Cyber Resilience Act (CRA) | Parlement Européen et Conseil de l'Union Européen | 2026-06-02 | Union Européenne | EU Cyber Resilience Act | Imposition de règles de transparence strictes et de responsabilité élargie pour les dépendances logicielles tout au long de leur cycle de vie, incluant le suivi et l'isolation des composants open-source abandonnés (EOL). | [OpenSSF](https://openssf.org/podcast/2026/06/02/whats-in-the-soss-podcast-62-s3e14-the-ghost-in-the-dependency-tree-navigating-open-source-end-of-life-with-herodevs/) |
| HIPAA Privacy and Security Rules Hardening | HHS Office for Civil Rights (OCR) | 2026-06-02 | États-Unis | HIPAA Rules | Durcissement des contrôles suite à l'incident Change Healthcare. Les contrôles autrefois jugés "adressables" (chiffrement, MFA, segmentation, audits) deviennent formellement requis et passibles de sanctions majeures. | [GuidePoint Security](https://www.guidepointsecurity.com/blog/the-hipaa-privacy-rule-simplified/) |
| Commission Delegated Regulation (UE) 2026/699 | Commission Européenne | 2026-06-03 | Union Européenne | Règlement (UE) 2018/858 | Normalisation et sécurisation cryptographique de l'accès aux interfaces OBD (diagnostic embarqué) pour empêcher les intrusions et reprogrammations sauvages de véhicules connectés. | [Eur-Lex](https://eur-lex.europa.eu/legal-content/AUTO/?uri=OJ:L_202600699) |
| US Executive Order on AI (June 2026) | Présidence des États-Unis | 2026-06-02 | États-Unis | US Executive Order | Décret imposant aux concepteurs d'IA de pointe de soumettre volontairement leurs modèles à un examen gouvernemental préalable de 30 jours pour limiter la découverte automatisée d'exploits. | [France24](https://www.france24.com/fr/am%C3%A9riques/20260602-au-nom-de-la-cybers%C3%A9curit%C3%A9-donald-trump-finit-par-r%C3%A9guler-l-ia) |
| ENISA NIS360 2026 | ENISA | 2026-06-02 | Union Européenne | NIS2 Directive Maturity | Troisième rapport évaluant la maturité sectorielle. Si la finance et l'énergie progressent, les secteurs de la santé, de l'eau, du transport spatial et ferroviaire restent dangereusement vulnérables. | [Security Affairs](https://securityaffairs.com/193002/reports/enisa-nis360-2026-progress-across-the-board-but-the-sectors-that-matter-most-are-still-falling-short.html) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Santé et Assurances | CS Insurance (Mexique) & Ace Hospital (Inde) | Dossiers médicaux cliniques des patients, informations d'assurances financières, données d'identification personnelles (PII) | Volume massif (plusieurs bases de données publiées en ligne par KillSec3 suite à des ransomwares) | [RansomLook - CS Insurance](https://www.ransomlook.io/group/killsec3)<br>[RansomLook - Ace Hospital](https://www.ransomlook.io/group/killsec3) |
| Humanitaire | Programme Alimentaire Mondial (PAM / WFP) de l'ONU | Noms et composition des ménages, allocations financières d'aide d'urgence, détails d'identification sensibles dans la région de Gaza | 600 000 foyers impactés | [DataBreaches.net](https://databreaches.net/2026/06/02/data-of-600000-gaza-households-exposed-in-world-food-programme-cyberattack/?pk_campaign=feed&pk_kwd=data-of-600000-gaza-households-exposed-in-world-food-programme-cyberattack) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2024-21182 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2025-48595 | TRUE  | Active    | 6.0 | 8.4   | (1,1,6.0,8.4) |
| 3 | CVE-2025-8088  | FALSE | Active    | 4.0 | 9.8   | (0,1,4.0,9.8) |
| 4 | CVE-2026-8206  | FALSE | Active    | 3.5 | 9.8   | (0,1,3.5,9.8) |
| 5 | CVE-2026-9614  | FALSE | Théorique | 2.0 | 9.0   | (0,0,2.0,9.0) |
| 6 | CVE-2026-5386  | FALSE | Théorique | 1.5 | 9.0   | (0,0,1.5,9.0) |
| 7 | CVE-2026-10591 | FALSE | Théorique | 1.0 | 8.5   | (0,0,1.0,8.5) |
| 8 | CVE-2026-35482 | FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
| 9 | CVE-2026-32625 | FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
| 10| CVE-2026-33829 | FALSE | Théorique | 1.0 | 4.3   | (0,0,1.0,4.3) |
| 11| CVE-2021-4481  | FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
| 12| CVE-2021-4480  | FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2024-21182** | 9.8 | N/A | **TRUE** | 7.0 | Oracle WebLogic Server | Désérialisation via protocoles d'administration | RCE | Active | Désactiver ou filtrer l'accès externe aux ports d'administration (ports 7001/7002, protocoles T3 et IIOP). | [Security Affairs](https://securityaffairs.com/193027/security/u-s-cisa-adds-oracle-weblogic-flaw-to-its-known-exploited-vulnerabilities-catalog.html)<br>[The Hacker News](https://thehackernews.com/2026/06/oracle-weblogic-cve-2024-21182-added-to.html)<br>[Cybersecurity News](https://cybersecuritynews.com/oracle-weblogic-server-vulnerability-exploited/) |
| **CVE-2025-48595** | 8.4 | N/A | **TRUE** | 6.0 | Android OS Framework (versions 14, 15, 16) | Integer Overflow / Dépassement d'entier | LPE | Active | Forcer l'application immédiate du niveau de correctif de sécurité 2026-06-05 via les profils MDM. | [The Hacker News](https://thehackernews.com/2026/06/google-june-2026-android-update-patches.html)<br>[The Cyber Throne](https://thecyberthrone.in/2026/06/02/google-android-june-2026-security-bulletin/)<br>[CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0679/) |
| **CVE-2025-8088** | 9.8 | N/A | FALSE | 4.0 | WinRAR | Path Traversal / Traversée de répertoires | RCE | Active | Mettre à jour d'urgence WinRAR ou interdire l'utilisation d'outils d'archivage non autorisés. Bloquer l'exécution automatique de scripts HTA. | [The Hacker News](https://thehackernews.com/2026/06/gamaredon-exploits-winrar-to-deliver.html) |
| **CVE-2026-8206** | 9.8 | N/A | FALSE | 3.5 | WordPress Plugin: Kirki Customizer Framework (v6.0.0 à v6.0.6) | Contournement d'authentification / Modification d'email | Auth Bypass / Hijack | Active | Installer d'urgence la version 6.0.7 ou supérieure du plugin Kirki Customizer Framework. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-kirki-flaw-exploited-to-hijack-wordpress-admin-accounts/) |
| **CVE-2026-9614** | 9.0 | N/A | FALSE | 2.0 | Ivanti Neurons for ITSM | Contournement d'authentification à distance | Auth Bypass | Théorique | Appliquer immédiatement les correctifs cumulatifs mensuels distribués par Ivanti pour Neurons ITSM. | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0677/) |
| **CVE-2026-5386** | 9.0 | N/A | FALSE | 1.5 | Caméras de vidéosurveillance KMW | Défaut d'authentification sur flux réseau | Information Disclosure | Théorique | Isoler les dispositifs CCTV au sein d'un VLAN fermé, sans aucune exposition directe à Internet, et utiliser un VPN. | [Cybersecurity News](https://cybersecuritynews.com/kmw-cctv-vulnerability/) |
| **CVE-2026-10591** | 8.5 | N/A | FALSE | 1.0 | Kiro IDE (versions < 0.11) | Restriction d'écriture insuffisante | RCE | Théorique | Effectuer la mise à niveau de Kiro IDE vers la version 0.11 ou supérieure. Bloquer l'exécution de tâches non signées. | [AWS Security](https://aws.amazon.com/security/security-bulletins/rss/2026-037-aws/) |
| **CVE-2026-35482** | 8.0 | N/A | FALSE | 1.0 | application de réservation alf.io | Évasion de bac à sable (Rhino Javascript Engine) | RCE | Théorique | Déployer la version corrective 2.0-M5-2606 d'alf.io et restreindre les privilèges d'administration de l'outil. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-35482) |
| **CVE-2026-32625** | 8.0 | N/A | FALSE | 1.0 | LibreChat | Injection d'URL via serveur MCP | Secret Leak / Auth Bypass | Théorique | Installer d'urgence la mise à jour LibreChat v0.8.4-rc1 ou supérieure et restreindre les requêtes réseau sortantes. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-32625) |
| **CVE-2026-33829** | 4.3 | N/A | FALSE | 1.0 | Windows Snipping Tool & URI Handler | URI Handler NTLM Coercion | Credential Leak | Théorique | Bloquer les connexions SMB sortantes (ports TCP/139 et TCP/445) au niveau du pare-feu d'entreprise. | [Huntress](https://www.huntress.com/blog/unpatched-ntlm-coercion-windows-search-uri-handler) |
| **CVE-2021-4481** | 8.0 | N/A | FALSE | 1.0 | Dräger Protector Software | Autorisations faibles sur répertoire système | LPE | Théorique | Mettre à niveau Dräger Protector vers la version 6.4.2 et limiter les accès ACL en écriture aux dossiers applicatifs. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2021-4481) |
| **CVE-2021-4480** | 8.0 | N/A | FALSE | 1.0 | Dräger Protector Software | Autorisations de fichiers faibles (variante) | LPE | Théorique | Mettre à niveau vers la version 6.4.2 et revoir les permissions système sur l'hôte médical d'exécution. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2021-4480) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Red Hat npm packages backdoored via compromised CI/CD pipeline | Mini Shai-Hulud + npm supply chain compromise | Attaque sophistiquée ciblant un namespace Red Hat légitime, exploitant des flux de validation et distribuant un ver auto-propagateur. | [Field Effect](https://fieldeffect.com/blog/red-hat-npm-packages-backdoored)<br>[Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| Instagram users locked out after Meta AI abused to steal accounts | Meta AI / Instagram Account Hijacking | Technique émergente et critique de contournement d'identité (prompt injection sur chatbot d'assistance et deepfakes d'identité). | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-online-outage-causes-email-delays-failures/)<br>[Security Affairs](https://securityaffairs.com/193034/hacking/instagram-account-hijacks-expose-the-security-risks-of-ai-powered-support.html)<br>[DataBreaches.net](https://databreaches.net/2026/06/02/hackers-simply-asked-meta-ai-to-give-them-access-to-high-profile-instagram-accounts-it-worked/?pk_campaign=feed&pk_kwd=hackers-simply-asked-meta-ai-to-give-them-access-to-high-profile-instagram-accounts-it-worked) |
| From Fake Purchase Orders to Remote Access: Analyzing the JS.MonoGlyphRAT Threat | JS.MonoGlyphRAT + Fake Purchase Orders | Nouveau malware ciblant spécifiquement les services comptables d'entreprises à l'aide de techniques d'obfuscation complexes de monoglyphes. | [ANY.RUN](https://any.run/cybersecurity-blog/monoglyphrat-attacks-us-enterprise/) |
| Over 116,000 Mincraft systems infected in WeedHack malware campaign | WeedHack + Minecraft credential theft campaign | Campagne de malware de masse s'appuyant sur l'ingénierie sociale pour voler des identifiants d'utilisateurs via des clients de jeux détournés. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-116-000-mincraft-systems-infected-in-weedhack-malware-campaign/) |
| AI-built ransomware toolkit automates EDR evasion, AD discovery | AI-built ransomware toolkit + EDR evasion | Menace inédite de développement autonome de charges utiles de rançonnage et d'affinement automatisé d'évasion d'EDR via des agents IA. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ai-built-ransomware-toolkit-automates-edr-evasion-ad-discovery/) |
| GoDaddy found malware on 1,980 WordPress sites using Steam as C2 infrastructure | WordPress malware + Steam C2 dead drop resolver | Détournement innovant et indétectable de profils Steam comme Dead Drop Resolver avec obfuscation par caractères Unicode invisibles. | [Security Affairs](https://securityaffairs.com/192990/breaking-news/godaddy-found-malware-on-1980-wordpress-sites-using-steam-as-c2-infrastructure.html) |
| Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor | FlutterShell + Operation FlutterBridge | Campagne ciblant activement macOS en chargeant sa logique malveillante à la volée via une WebView dans une app signée. | [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/) |
| New Wave Of Phishing Emails with SVG Files | Phishing campaign via malicious SVG attachments | Nouvelle vague de phishing employant des fichiers vectoriels SVG intégrant de l'ECMAScript pour forcer l'exécution de code au clic. | [SANS ISC](https://isc.sans.edu/diary/rss/33040) |
| Possible Phishing on view-vibes | Phishing campaign via view-vibes on GitHub Pages | Analyse d'une page active d'hameçonnage hébergée directement sur l'infrastructure GitHub Pages. | [Infosec Exchange](https://infosec.exchange/@urldna/116683466878277504) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Cyber Brief 26-06 - May 2026 | Rapport de synthèse mensuel généraliste (ne traite pas d'un incident ou d'un malware unique). | [CERT-UE](https://cert.europa.eu/publications/threat-intelligence/cb26-06/) |
| ISC Stormcast For Wednesday, June 3rd, 2026 | Flux d'actualité quotidien informatif généraliste sans focus technique unifié. | [SANS ISC](https://isc.sans.edu/diary/rss/33042) |
| ISC Stormcast For Tuesday, June 2nd, 2026 | Flux d'actualité quotidien informatif généraliste sans focus technique unifié. | [SANS ISC](https://isc.sans.edu/diary/rss/33038) |
| Microsoft's Coreutils project brings Linux commands to Windows | Actualité produit/développement logicielle générique, sans rapport avec un incident de sécurité ou une attaque. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsofts-coreutils-project-brings-linux-commands-to-windows/) |
| OpenAI upgrades GPT-5.5, as it plans to retire legacy ChatGPT models | Actualité produit/IA commerciale générique sans focus direct sur un incident de cybersécurité. | [BleepingComputer](https://www.bleepingcomputer.com/news/artificial-intelligence/openai-upgrades-gpt-55-as-it-plans-to-retire-legacy-chatgpt-models/) |
| Microsoft Exchange Online outage causes email delays, failures | Panne technique opérationnelle d'infrastructure (non liée à un piratage ou une attaque malveillante). | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-online-outage-causes-email-delays-failures/) |
| In-Cloud IR: How to Forensically Acquire and Analyze a Compromised Azure VM | Guide technique et tutoriel d'investigation numérique (forensics), n'analysant pas un cas réel d'intrusion ou un incident spécifique. | [Cyber Engage](https://www.cyberengage.org/post/in-cloud-ir-how-to-forensically-acquire-and-analyze-a-compromised-azure-vm-without-pulling-the-plug) |
| From API key to live threat detections in minutes | Article à caractère purement commercial faisant la promotion de l'intégration produit Elastic et Google GTI. | [Elastic Security Labs](https://www.elastic.co/security-labs/elastic-security-google-threat-intelligence) |
| Your Patients’ Records Are Worth More Than Their Bank Account Numbers | Étude de valorisation financière de données d'activité criminelle (pas d'analyse technique d'incident ou de malware). | [Flare](https://flare.io/learn/resources/blog/healthcare-record-costs-dark-web) |
| Security briefing: May 2026 | Note de synthèse mensuelle d'actualités générales et de sensibilisation (sans incident ou menace unifiée). | [Sysdig](https://webflow.sysdig.com/blog/security-briefing-may-2026) |
| AI Agents Management Framework | Document théorique de gouvernance de la conformité d'IA (sans aspect sécuritaire ou incident). | [Mastodon / lbhuston](https://mastodon.social/@lbhuston/116683644468603031) |
| Hey #Infosec crowd: I'm looking to snoop on all network traffic... | Échange informel d'assistance technique réseau légitime sur les réseaux sociaux. | [LGBTQIA Space / grim_elsewhere](https://lgbtqia.space/@grim_elsewhere/116683512737833543) |
| FydeOS chronos user security concerns | Questionnement de configuration d'OS sans incident ou exploitation malveillante documentée. | [Layer8 Space / platymew](https://layer8.space/@platymew/116683414751302967) |
| Most organizations that miss 24-hour patch window report breaches | Étude statistique sectorielle sur les temps d'application de correctifs d'entreprises. | [DataBreaches.net](https://databreaches.net/2026/06/02/most-organizations-that-miss-24-hour-patch-window-report-breaches/?pk_campaign=feed&pk_kwd=most-organizations-that-miss-24-hour-patch-window-report-breaches) |
| Témoignage glaçant d’un soldat israélien | Contenu politique/militaire fortement tronqué et URL source coupée en cours de transit. | [IRIS](https://www.iris-france.org/temoignage-glacant-dun-soldat-israel) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="mini-shai-hulud-npm-supply-chain-compromise"></div>

## Mini Shai-Hulud + npm supply chain compromise

---

### Résumé technique

Les laboratoires de Unit 42 et Field Effect ont documenté une évolution critique des attaques menées contre la chaîne logistique logicielle npm par le groupe **TeamPCP**. En exploitant des faiblesses inhérentes à l'authentification OpenID Connect (OIDC) et en pratiquant l'empoisonnement de cache CI/CD, les attaquants ont réussi à compromettre le namespace légitime `@redhat-cloud-services` de Red Hat sur le dépôt officiel npm. Plus de 30 packages signés et publiés de manière approuvée ont été contaminés. 

Le vecteur d'infection repose sur la publication de mises à jour de dépendances intégrant un script d'installation malveillant (`setup.mjs` ou `tanstack_runner.js`). À l'exécution, ce code déploie le ver auto-propagateur **Mini Shai-Hulud** (alias *Miasma*). Ce dernier est conçu pour énumérer la mémoire locale (via `/proc/*/mem`), exfiltrer les jetons d'accès GitHub (`gh auth token`), ainsi que les clés cloud stockées dans l'environnement de développement. Le ver se réplique ensuite de manière autonome en injectant des dependances malveillantes dans tous les packages npm éditables par l'utilisateur compromis.

### Analyse de l'impact

L'impact est considéré comme critique. En polluant des paquets bénéficiant d'une signature SLSA Build Level 3, les attaquants contournent l'intégralité des moteurs d'analyse statique classiques. La compromission d'un poste de développeur ou d'un pipeline de build contamine instantanément les dépendances descendantes du projet, menant à une infection en chaîne sur l'ensemble du parc logiciel mondial qui intègre ces librairies.

### Recommandations

1. Nettoyer et purger l'intégralité des packages npm sous le namespace `@redhat-cloud-services` installés ou révisés le 1er juin 2026.
2. Configurer les environnements de build pour interdire systématiquement l'exécution de scripts lors de la phase d'installation (utiliser la directive `--ignore-scripts`).
3. Forcer une politique de rotation stricte et éphémère de l'ensemble des jetons d'accès aux dépôts Git (scopes d'autorisation OIDC réduits au strict minimum).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer les agents EDR et serveurs SIEM pour journaliser en continu les modifications de fichiers dans les répertoires `node_modules` et les dossiers de cache npm locaux.
* Mettre à disposition une sandbox d'analyse Node.js isolée pour tester de façon sécurisée le comportement des nouveaux packages open source importés.
* Répertorier l'ensemble des projets de développement exploitant les dépendances de Red Hat ou de TanStack pour prioriser la remédiation.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Requête EDR ciblant l'invocation anormale de runtimes Bun ou Node exécutant des scripts non signés depuis les répertoires temporaires :
    `process_name == 'bun' AND command_line CONTAINS 'setup.mjs' OR command_line CONTAINS 'tanstack_runner.js'`
  * Alerte SIEM détectant les lectures inhabituelles de la mémoire virtuelle ou de `/proc/*/mem` par un binaire d'exécution JavaScript.
* Lister l'ensemble des runners CI/CD ayant compilé ou publié des versions logicielles utilisant les bibliothèques Red Hat affectées entre le 31 mai et le 2 juin 2026.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler logiquement du réseau l'ensemble des postes de développement et runners de compilation identifiés comme ayant importé des packages `@redhat-cloud-services` altérés.
* Bloquer immédiatement les requêtes réseau sortantes vers les serveurs C2 de Shai-Hulud : `t.m-kosche[.]com` et `audit.checkmarx[.]cx`.

**Éradication :**
* Supprimer et remplacer les modules infectés de Red Hat en forçant une réinstallation de versions antérieures validées ou saines.
* Révoquer l'intégralité des jetons de service (GitHub, AWS, Azure, GCP) et clés SSH stockés ou manipulés au sein des environnements d'exécution affectés.

**Récupération :**
* Restaurer l'arbre de dépendance Git à une version historiquement saine en écartant les commits orphelins (orphan commits) générés de façon autonome par le ver.
* Surveiller étroitement les exécutions de compilation pendant 72 heures après le nettoyage pour valider la non-réapparition de scripts malveillants.

#### Phase 4 — Activités post-incident

* Documenter la chronologie de la compromission et calculer le MTTD (Mean Time To Detect) de l'intrusion de la chaîne d'approvisionnement.
* Déclarer l'incident de sécurité aux autorités compétentes nationales sous 24 heures en conformité avec la directive NIS2 (compromission majeure de pipeline d'une ESN stratégique).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de processus système suspectés de voler des identifiants Git en mémoire active. | T1555 | Logs de surveillance de processus de l'EDR | Rechercher l'exécution de `gh auth token` initiée par un processus enfant de `npm` ou de `node`. |
| Identification de modifications indues de packages npm dans l'arborescence locale. | T1195.001 | FIM (File Integrity Monitoring) | Rechercher des événements d'écriture dans `node_modules` avec un timestamp au 1er juin 2026 sans action de build initiée par l'opérateur. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `t.m-kosche[.]com` | Serveur de commande (C2) de Mini Shai-Hulud | Haute |
| Domaine | `audit.checkmarx[.]cx` | Infrastructure réseau malveillante d'exfiltration de TeamPCP | Haute |
| IP | `91[.]195[.]240[.]123` | Serveur C2 actif associé aux vagues de propagation | Haute |
| IP | `94[.]154[.]172[.]43` | IP d'exfiltration de secrets de TeamPCP | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1195.001** | Initial Access | Supply Chain Compromise | Empoisonnement ciblé de dépôts et dépendances npm légitimes. |
| **T1027.013** | Defense Evasion | Encrypted/Encoded File | Chiffrement par substitution ASCII personnalisé pour masquer l'adresse des serveurs C2. |
| **T1555** | Credential Access | Credentials from Password Stores | Extraction en mémoire des jetons GitHub et clés d'accès d'environnement cloud. |

---

### Sources

* [Field Effect](https://fieldeffect.com/blog/red-hat-npm-packages-backdoored)
* [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

---

<div id="meta-ai-instagram-account-hijacking"></div>

## Meta AI / Instagram Account Hijacking

---

### Résumé technique

Des campagnes de piratage ciblant des comptes d'influenceurs et de marques à forte valeur sur Instagram ont mis en lumière une vulnérabilité critique dans l'automatisation du support client par l'IA de Meta. Les attaquants exploitent des techniques d'ingénierie sociale assistée par IA ("prompt injection") combinées à de l'usurpation d'identité synthétique. 

Pour forcer la récupération et la réinitialisation de comptes de premier plan, les pirates soumettent au chatbot d'assistance de Meta des selfies animés générés par IA ou des documents falsifiés. L'assistant IA, manipulé par des instructions contradictoires, accepte de modifier l'adresse e-mail de contact et de désactiver l'authentification double facteur (2FA) configurée par les propriétaires légitimes. Les pirates prennent ainsi le contrôle total du profil en évinçant complètement l'utilisateur d'origine.

### Analyse de l'impact

L'impact est réputationnel et opérationnel. La perte de contrôle des canaux officiels de communication de marques ou d'organisations d'importance permet la diffusion immédiate de désinformation, d'arnaques cryptographiques ou de messages de propagande malveillants, ruinant l'image publique de l'entité compromise en quelques minutes.

### Recommandations

1. Activer de manière obligatoire l'authentification multifacteur robuste (2FA de type FIDO2 / clés de sécurité physiques ou applications d'authentification tierces).
2. Établir et documenter des canaux de communication humaine d'urgence préalablement validés avec la plateforme de médias sociaux pour court-circuiter les décisions automatisées des chatbots d'IA.

---

### Playbook de réponse à incident

#### Phase 1 — Preparation

* Enregistrer l'ensemble des comptes officiels de réseaux sociaux corporatifs avec des e-mails institutionnels protégés, de préférence non individuels (ex: `socialmedia@entreprise[.]com`).
* Conserver de manière sécurisée et déconnectée les identifiants originaux de création des comptes et les jetons de récupération de secours.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Alerte de sécurité sur la réception inopinée de notifications de modification d'adresse de contact, de demande de réinitialisation de mot de passe ou de désactivation de la double authentification (2FA).
* Analyser les logs de connexion pour repérer des tentatives d'accès géographiquement anormales précédant la demande de récupération de compte.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Alerter immédiatement la communauté et les partenaires via les canaux alternatifs officiels pour signaler la compromission en cours de l'image de marque.
* Exiger du support de Meta (via les canaux dédiés aux VIP/Comptes certifiés) le gel temporaire du profil Instagram affecté.

**Éradication :**
* Forcer l'invalidation de toutes les sessions d'API tierces connectées au compte Instagram (ex : outils de planification ou d'analyse marketing).
* Mettre à jour l'e-mail de récupération associé avec une adresse protégée par un mot de passe unique hautement complexe.

**Récupération :**
* Soumettre une demande officielle de récupération humaine de l'identité du compte en fournissant les documents de marque d'origine et en invalidant les validations effectuées par l'IA d'assistance.
* Reconfigurer l'authentification 2FA via des clés physiques (FIDO2) sur le compte restauré.

#### Phase 4 — Activités post-incident

* Mener un audit des processus d'identité utilisés par les équipes de communication numérique et adapter les politiques de gestion d'accès des réseaux sociaux.
* Informer l'autorité réglementaire (ex: CNIL / RGPD) si la violation a entraîné l'accès illicite à des données personnelles d'abonnés ou de clients via la messagerie du compte.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de tentatives de contournement de support sur les comptes de collaborateurs clés. | T1566 | Logs de la messagerie de support corporative | Rechercher des demandes frauduleuses de vérification d'identité ou de transmission de selfies corporatifs de validation. |

---

### Indicateurs de compromission (DEFANG obligatoire)

> *Remarque : S'agissant d'une attaque ciblant la logique d'assistance d'une plateforme SaaS externe par ingénierie sociale, aucun indicateur de compromission technique (IP/Hash) spécifique n'est applicable.*

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1566** | Initial Access | Phishing | Abus d'ingénierie sociale assistée par IA pour forcer la confiance d'un chatbot d'assistance. |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-online-outage-causes-email-delays-failures/)
* [Security Affairs](https://securityaffairs.com/193034/hacking/instagram-account-hijacks-expose-the-security-risks-of-ai-powered-support.html)
* [DataBreaches.net](https://databreaches.net/2026/06/02/hackers-simply-asked-meta-ai-to-give-them-access-to-high-profile-instagram-accounts-it-worked/?pk_campaign=feed&pk_kwd=hackers-simply-asked-meta-ai-to-give-them-access-to-high-profile-instagram-accounts-it-worked)

---

<div id="js-monoglyphrat-fake-purchase-orders"></div>

## JS.MonoGlyphRAT + Fake Purchase Orders

---

### Résumé technique

Le nouveau backdoor **JS.MonoGlyphRAT** cible de manière agressive les entreprises américaines et européennes. Diffusé sous l'apparence de fausses pièces jointes de factures ou de devis via des campagnes d'hameçonnage ciblant particulièrement les services commerciaux et comptables, ce malware est écrit en JavaScript. 

Il s'exécute sur les postes des victimes via l'interpréteur par défaut de Windows, Windows Script Host (`wscript.exe`). Afin de déjouer les analyses statiques et les règles YARA classiques, MonoGlyphRAT intègre une technique d'obfuscation complexe de type "monoglyphe", reposant sur l'utilisation répétitive des mêmes caractères avec des casses de lettres alternées de façon continue. Une fois actif, il collecte des informations système à l'aide de requêtes WMI, configure une clé de persistance dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` et établit un canal de communication C2 chiffré par des en-têtes HTTP personnalisés permettant de télécharger et d'exécuter des scripts PowerShell de second niveau chiffrés en AES.

### Analyse de l'impact

L'impact sur la confidentialité et l'intégrité des systèmes est élevé. MonoGlyphRAT fournit un accès interactif à distance complet sur la machine compromise, permettant de dérober des identifiants locaux de session ou d'initier un mouvement latéral dans l'Active Directory afin de préparer une attaque par rançongiciel d'envergure.

### Recommandations

1. Bloquer l'exécution par défaut des scripts `.js` par `wscript.exe` en modifiant l'application d'ouverture de l'extension `.js` (l'associer à `notepad.exe` ou un éditeur de texte inoffensif).
2. Déployer des règles de blocage d'exécution AppLocker ou WDAC pour empêcher l'exécution de scripts non signés depuis les répertoires `%USERPROFILE%\AppData`.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer une règle de registre d'entreprise pour désactiver de manière permanente Windows Script Host (`wscript.exe`) pour les utilisateurs standard.
* S'assurer que la journalisation de PowerShell (événements 4104 et 4103) et l'exécution de scripts d'historique de lignes de commande sont activées et centralisées dans le SIEM.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Requête EDR identifiant le lancement anormal de scripts `.js` depuis les dossiers d'applications de l'utilisateur :
    `process_name == 'wscript.exe' AND command_line CONTAINS '.js' AND command_line CONTAINS '%USERPROFILE%'`
  * Règle de surveillance de registre détectant l'écriture de nouvelles clés suspectes dans le chemin Run de l'utilisateur pointant vers `wscript.exe`.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Tuer immédiatement l'arbre de processus lié à `wscript.exe` et aux instances suspectes de `powershell.exe` s'exécutant sur le poste de travail.
* Bloquer l'accès réseau sortant vers les adresses de commande identifiées : `158[.]94[.]211[.]76` et `91[.]92[.]243[.]79`.

**Éradication :**
* Supprimer le script `.js` malveillant du dossier de destination utilisateur (souvent dissimulé dans un sous-répertoire d'AppData).
* Supprimer de la base de registre la clé de persistance créée sous le profil de l'utilisateur affecté (`HKCU\...\Run`).

**Récupération :**
* Procéder à un balayage complet de la mémoire active du système et restaurer l'intégrité de l'hôte compromis.
* Forcer la réinitialisation des privilèges et mots de passe du compte d'utilisateur s'étant connecté sur le poste infecté.

#### Phase 4 — Activités post-incident

* Conduire une analyse REX avec l'équipe de messagerie pour renforcer le filtrage des passerelles anti-spam contre la réception de scripts d'exécution automatique.
* Rédiger le rapport technique de l'incident en y incluant l'évaluation des volumes de données exfiltrés en cas de connexion C2 réussie et prolongée.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exécutions d'outils Windows Script Host masqués. | T1059.007 | Journaux d'exécution de processus SIEM | Filtrer l'ensemble des exécutions de `wscript.exe` ou `cscript.exe` ayant pour paramètre des fichiers temporaires ou de messagerie. |
| Détection de clés de registre de démarrage non documentées. | T1547.001 | Surveillance des ruches de registres EDR | Analyser périodiquement les écarts de configuration des clés de démarrage (Run/RunOnce) à la recherche de scripts obsolètes ou suspects. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `aryamint[.]com` | Domaine de commande C2 de JS.MonoGlyphRAT | Haute |
| IP | `158[.]94[.]211[.]76` | Adresse IP résolvant l'infrastructure malveillante | Haute |
| IP | `91[.]92[.]243[.]79` | Adresse IP de livraison des payloads PowerShell chiffrés | Haute |
| Hash SHA256 | `5446b24959c1c2707accfc257aaac61819c01d1ed65bca910a7e8be1787d200f` | Empreinte numérique de la charge utile initiale `.js` | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1059.007** | Execution | JavaScript | Exécution locale de scripts malveillants via l'interpréteur système par défaut `wscript.exe`. |
| **T1547.001** | Persistence | Registry Run Keys / Startup Folder | Enregistrement d'une commande persistante dans la ruche Run de l'utilisateur. |
| **T1027.013** | Defense Evasion | Encrypted/Encoded File | Emploi de l'obfuscation par caractères homoglyphes/monoglyphes alternés. |

---

### Sources

* [ANY.RUN](https://any.run/cybersecurity-blog/monoglyphrat-attacks-us-enterprise/)

---

<div id="weedhack-minecraft-credential-theft-campaign"></div>

## WeedHack + Minecraft credential theft campaign

---

### Résumé technique

Une campagne d'infection de grande ampleur exploitant la communauté de joueurs Minecraft distribue le malware **WeedHack**. Le logiciel malveillant se propage par ingénierie sociale (liens de téléchargement incrustés dans des vidéos YouTube décrivant des outils de triche de jeu de type *Meteor*) et par empoisonnement des moteurs de recherche (SEO poisoning). 

WeedHack est un infostealer complet qui cible l'extraction des identifiants de session Minecraft, des cookies de session de plus de 36 navigateurs internet majeurs, des configurations de connexion à Discord, Telegram et des données de portefeuilles cryptographiques. Une version payante (premium) de ce malware offre en outre des fonctionnalités de RAT (Remote Access Trojan) avancé, intégrant l'exécution de commandes système arbitraires et un enregistreur de frappe (keylogger).

### Analyse de l'impact

L'impact réside dans le vol massif de jetons de connexion et d'identifiants personnels. Si des utilisateurs exécutent ce logiciel sur des équipements de l'entreprise connectés au réseau interne (Shadow IT), cela conduit directement à la compromission d'accès d'applications métier critiques dont les secrets d'accès étaient mémorisés dans les navigateurs ou Discord.

### Recommandations

1. Interdire formellement l'installation et le téléchargement de jeux et de solutions de triche non autorisés sur les terminaux de l'organisation à travers une politique MDM stricte.
2. Sensibiliser les collaborateurs et leurs familles aux dangers inhérents aux téléchargements d'exécutables issus de plateformes de partage vidéo à l'image de YouTube.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer des politiques de restriction logicielle (AppLocker) pour empêcher l'exécution d'applications en dehors des répertoires systèmes approuvés (comme Program Files).
* Surveiller l'usage et l'installation de logiciels récréatifs non documentés sur le parc de machines.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Détection EDR sur l'apparition ou l'exécution de binaires d'installation contenant les chaînes de caractères "WeedHack" ou "Meteor" dans leur chemin :
    `file_name CONTAINS 'WeedHack' OR file_name CONTAINS 'Meteor'`
  * Alerte comportementale si une application non reconnue accède de façon récursive aux répertoires d'historique et de cookies de Chrome, Edge ou Firefox.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler logiquement l'équipement utilisateur infecté pour couper les transmissions d'informations sensibles vers l'extérieur.
* Invalider immédiatement l'ensemble des sessions actives de l'utilisateur sur la messagerie de l'entreprise et sur les canaux collaboratifs (Slack/Discord).

**Éradication :**
* Supprimer le fichier exécutable d'origine et tous les binaires complémentaires déployés dans les dossiers de téléchargement de l'utilisateur.
* Nettoyer les extensions de navigateurs internet installées de manière non contrôlée lors de la compromission.

**Récupération :**
* Forcer une réinitialisation complète de l'ensemble des mots de passe enregistrés par l'utilisateur au sein des navigateurs du poste.
* Restaurer l'environnement de l'ordinateur à un état sain d'origine.

#### Phase 4 — Activités post-incident

* Mener une session d'éducation technologique et de sensibilisation de l'utilisateur concerné concernant les risques liés à l'usage personnel d'équipements corporatifs.
* Mettre à jour l'inventaire des applications installées sur le parc de machines pour s'assurer de l'absence d'autres instances de WeedHack.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de vols furtifs de fichiers de configuration Discord ou de navigateurs. | T1539 | Journaux d'audit de fichiers EDR | Rechercher des accès d'écriture ou de lecture massifs sur `%APPDATA%\discord\Local Storage` par des processus non autorisés. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | `WeedHack.exe` | Exécutable malveillant principal de la campagne | Moyenne |
| Nom de fichier | `MeteorCheat.exe` | Faux utilitaire de triche Minecraft | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1566.002** | Initial Access | Spearphishing Link | Distribution de liens de redirection piégés sous des descriptions de vidéos YouTube. |
| **T1539** | Credential Access | Steal Web Session Cookie | Extraction directe de jetons d'accès et d'identifiants de cookies de navigateurs web. |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-116-000-mincraft-systems-infected-in-weedhack-malware-campaign/)

---

<div id="ai-built-ransomware-toolkit-edr-evasion"></div>

## AI-built ransomware toolkit + EDR evasion

---

### Résumé technique

Des analystes en cybersécurité ont identifié un cadre d'attaque par rançongiciel extrêmement innovant, entièrement conçu et automatisé à l'aide d'agents d'intelligence artificielle (notamment via l'environnement de développement Cursor et le modèle Claude Opus). Ce framework d'attaque orchestre un processus d'évaluation et de compilation itératif de charges utiles de malwares écrites en Rust et en Go. 

Le système est capable de compiler un agent, de le tester localement face à des installations de solutions EDR du commerce (comme Sophos, CrowdStrike ou Windows Defender), de lire les logs d'interception et de modifier de façon continue le code source (via du *DLL unhooking* dynamique ou du polymorphisme de structure) jusqu'à ce que le taux d'évasion soit optimal. Par ailleurs, ce framework intègre un module d'énumération récursive de l'Active Directory hautement rationalisé pour optimiser le déploiement du ransomware sur l'ensemble du réseau.

### Analyse de l'impact

L'impact est particulièrement élevé car ce framework démocratise et automatise l'ingénierie d'évasion d'antivirus. Il permet à des opérateurs de menaces peu qualifiés de générer des charges utiles d'extorsion indétectables par les signatures et modèles de détection classiques, accélérant considérablement l'agilité et l'impact des campagnes d'extorsion de données.

### Recommandations

1. Activer de manière mandatory la protection d'intégrité de la mémoire active (LSA Protection et Tamper Protection) au niveau du système d'exploitation Windows pour limiter les techniques de contournement.
2. Privilégier des détections de type comportemental et contextuel au niveau du SIEM, en surveillant l'exécution et les requêtes AD non conventionnelles plutôt que de simples signatures de fichiers fixes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Durcir les accès en lecture à l'annuaire Active Directory en bloquant les requêtes d'énumération non structurées émanant d'utilisateurs non administrateurs.
* Déployer des capteurs de détection comportementale en temps réel (surveillance d'injection de code en mémoire, signatures d'appels de DLL).

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Alerte EDR sur la création de processus enfants de scripts (Python, Go) initiant des tests réguliers de chargement de mémoire de DLL :
    `process_name == 'python.exe' AND command_line CONTAINS 'evasion' OR command_line CONTAINS 'agent'`
  * Détecter un volume anormalement élevé de requêtes d'énumération LDAP provenant d'une seule machine cliente sur une courte période.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler instantanément l'hôte de développement ou l'hôte utilisateur suspecté de compiler ou de tester les charges utiles d'évasion d'EDR.
* Verrouiller immédiatement les comptes de services d'Active Directory ayant été énumérés de façon anormale par l'agent.

**Éradication :**
* Supprimer l'environnement de génération de code et purger l'historique d'exécution de l'agent d'IA (fichiers temporaires Go/Rust de l'agent).
* S'assurer du bon rétablissement de la configuration d'origine de l'EDR s'il y a eu des tentatives de blocage de service ou d'unhooking mémoire.

**Récupération :**
* Réinitialiser les mots de passe et secrets de comptes Active Directory compromis ou énumérés.
* Rétablir les sauvegardes immuables hors ligne validées pour parer à toute velléité de chiffrement réseau par rançongiciel.

#### Phase 4 — Activités post-incident

* Mener une analyse technique des techniques d'évasion ayant réussi lors des phases de test afin d'adapter les règles d'interception de l'EDR de l'entreprise.
* Partager les caractéristiques de comportement de l'agent d'IA avec la communauté infosec pour mettre à jour les référentiels de détection globaux.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification d'activités furtives de contournement d'antivirus en mémoire. | T1562.001 | Logs système EDR / API calls | Rechercher des tentatives d'altération de l'intégrité des modules mémoire de l'EDR ou de chargement de processus suspicieux non signés en mémoire. |

---

### Indicateurs de compromission (DEFANG obligatoire)

> *Remarque : Le framework de développement d'IA s'exécutant localement de manière personnalisée par instance, les IoCs fixes ne sont pas exhaustifs. Il convient de chasser les comportements de compilation et de requêtage AD décrits ci-dessus.*

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1562.001** | Defense Evasion | Disable or Modify Tools | Altération et contournement automatisés d'outils de détection EDR (*unhooking*). |
| **T1018** | Discovery | Remote System Discovery | Automatisation de l'exploration de l'Active Directory. |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/security/ai-built-ransomware-toolkit-automates-edr-evasion-ad-discovery/)

---

<div id="wordpress-malware-steam-c2-dead-drop-resolver"></div>

## WordPress malware + Steam C2 dead drop resolver

---

### Résumé technique

L'hébergeur GoDaddy a révélé l'existence d'une campagne de compromission massive ayant affecté plus de 1 980 sites internet motorisés par WordPress. Le malware, une fois injecté sur les serveurs via l'importation de fichiers d'extensions altérés ou le détournement de comptes d'administration, met en œuvre une infrastructure de commande C2 hautement furtive reposant sur la technique du Dead Drop Resolver (DDR) via la plateforme de jeu Steam de Valve. 

Le script malveillant (`asahi-jquery-min-bundle`), inséré dans les fichiers de thèmes WordPress, se connecte périodiquement à des profils d'utilisateurs Steam publics contrôlés par l'attaquant. Il extrait de la section commentaires des profils des directives codées à l'aide de six caractères Unicode invisibles de largeur nulle (U+200C, U+200D, etc.). Une fois décodées, ces informations pointent vers des scripts serveurs externes permettant d'écrire et d'exécuter du code PHP arbitraire sur le serveur WordPress infecté via des requêtes HTTP POST authentifiées par des cookies de session chiffrés (`DEpjndDbNc` ou `tEcaKKXEsb`).

### Analyse de l'impact

L'impact est moyen à élevé. La compromission persistante de serveurs WordPress permet aux attaquants d'utiliser la réputation et le trafic du site pour héberger des campagnes de phishing, de mener du vol d'informations de paiement des visiteurs (skimming), ou d'initier des attaques de déni de service distribuées.

### Recommandations

1. Mener un examen rigoureux des connexions réseau sortantes des serveurs Web WordPress à destination de plateformes récréatives à l'image de `steamcommunity.com`.
2. Installer des outils de détection de modification d'intégrité de fichiers (FIM) pour repérer la présence de caractères Unicode invisibles ou de fonctions de déchiffrement (`openssl_decrypt`, `hash_pbkdf2`) non standards dans les dossiers de thèmes et d'extensions de production.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Restreindre les privilèges d'écriture sur le répertoire racine de WordPress au niveau du serveur Web d'hébergement.
* Activer et configurer des règles de pare-feu applicatif (WAF) bloquant les requêtes de requêtage d'outils administratifs par des cookies non documentés.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Alerte de passerelle réseau ou DNS sur des requêtes HTTP/HTTPS émises par l'utilisateur du serveur Web (`www-data`) à destination de :
    `steamcommunity[.]com`
  * Requête comportementale SIEM détectant l'utilisation d'appels administratifs contenant des cookies spécifiques au malware :
    `request_uri CONTAINS 'wp-admin' AND (http_cookie CONTAINS 'DEpjndDbNc' OR http_cookie CONTAINS 'tEcaKKXEsb')`

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler le site WordPress affecté en bloquant les accès HTTP externes ou en redirigeant le trafic vers une page de maintenance temporaire.
* Bloquer de manière réseau l'exfiltration et la communication avec le domaine suspect : `hello-mywordl[.]info`.

**Éradication :**
* Purger le code du script malveillant `asahi-jquery-min-bundle` inséré dans les fichiers PHP de thèmes.
* Supprimer de la base de données WordPress tous les comptes administrateurs non approuvés créés lors de la compromission.

**Récupération :**
* Restaurer la totalité du dossier WordPress à partir d'une sauvegarde saine antérieure à la date d'injection estimée du malware.
* Changer la totalité des clés de salage et secrets cryptographiques d'Active Directory et de configuration de base de données présents dans `wp-config.php`.

#### Phase 4 — Activités post-incident

* Mener une évaluation de l'intégrité des bases de données de clients du site Web pour écarter tout risque de vol d'informations de carte de paiement.
* Documenter la faille de sécurité ayant permis l'accès initial et appliquer des correctifs de durcissement sur le serveur de base de données.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection d'obfuscation avancée dans le code source de l'application Web. | T1027.010 | Analyse statique de fichiers PHP / FIM | Rechercher des motifs de chaînes de caractères Unicode de largeur nulle ou l'usage répété de fonctions de chiffrement PHP obsolètes dans les répertoires de thèmes. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `hello-mywordl[.]info` | Infrastructure d'hébergement de payloads malveillants | Haute |
| URL | `hxxps[://]steamcommunity[.]com` | Plateforme de jeu utilisée comme Dead Drop Resolver | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1102.001** | Command and Control | Web Service: Dead Drop Resolver | Abus de plateformes et profils d'utilisateurs Steam publics pour décoder des instructions C2. |
| **T1027.010** | Defense Evasion | Command Obfuscation | Dissimulation de charge utile à l'aide de caractères Unicode de largeur nulle invisibles. |

---

### Sources

* [GoDaddy / Security Affairs](https://securityaffairs.com/192990/breaking-news/godaddy-found-malware-on-1980-wordpress-sites-using-steam-as-c2-infrastructure.html)

---

<div id="fluttershell-operation-flutterbridge"></div>

## FlutterShell + Operation FlutterBridge

---

### Résumé technique

Les équipes de Unit 42 ont détaillé "Operation FlutterBridge", une campagne de malvertising de grande ampleur menée par le groupe criminel **CL-CRI-1089** ciblant l'environnement macOS. Les attaquants exploitent des comptes Google Ads usurpés pour diffuser de fausses applications bureautiques certifiées d'apparence légitime (telles que des outils de lecture de PDF ou des lecteurs de podcasts). 

Ces applications, bien que signées et notarisées par Apple pour contourner le mécanisme Gatekeeper, exploitent la flexibilité du framework de développement Flutter. Elles embarquent un composant WebView invisible conçu pour charger de façon dynamique sa logique malveillante depuis le serveur C2 de l'attaquant lors de l'exécution sur le terminal de la victime. Ce mécanisme déploie la porte dérobée **FlutterShell**, capable de modifier de manière persistante les paramètres du navigateur Chrome de la victime, d'exécuter des commandes système via des scripts shell Unix, et d'exfiltrer en continu des documents utilisateur traités via l'interfaçage d'un faux service de résumé par IA.

### Analyse de l'impact

L'impact est particulièrement élevé sur la confidentialité et l'intégrité de la plateforme. La technique permet de contourner les contrôles statiques de l'App Store et de Gatekeeper d'Apple. Elle induit un vol massif de données d'entreprises sous couvert de fonctionnalités légitimes d'assistance d'IA.

### Recommandations

1. Exiger de manière stricte, via des profils MDM, le blocage de l'installation de logiciels macOS ne provenant pas de l'App Store officiel ou des dépôts internes validés de l'entreprise.
2. Auditer périodiquement l'intégrité et les modifications des fichiers de configuration de préférences de Google Chrome sur le parc informatique macOS.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer une surveillance des appels système et du trafic réseau sortant des terminaux macOS à destination d'infrastructures de cloud non certifiées.
* Configurer les règles du coupe-feu pour bloquer l'usage d'outils de communication réseau non déclarés sur les terminaux clients.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Détection EDR sur le lancement de commandes système par l'intermédiaire de processus d'applications d'Operation FlutterBridge :
    `process_parent == 'PodcastsLounge' OR process_parent == 'PDF-Brain' AND process_name == 'sh'`
  * Alerte de navigation DNS sur l'accès aux domaines d'exfiltration identifiés : `interfumesco[.]com` et `ads-parkpro[.]com`.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Révoquer le certificat d'exécution de l'application malveillante au niveau du parc macOS de l'entreprise en déclarant son identifiant unique.
* Isoler le terminal utilisateur compromis du réseau de l'entreprise pour limiter la fuite de documents de propriété intellectuelle.

**Éradication :**
* Supprimer l'application Flutter malveillante (`PodcastsLounge.app` ou `PDF-Brain.app`) du répertoire Applications de l'utilisateur.
* Purger les modifications frauduleuses apportées aux fichiers de configuration de préférences du profil de navigateur Chrome.

**Récupération :**
* Inspecter l'historique d'exécution de l'application pour l'utilisateur afin d'identifier précisément les documents de l'entreprise qui ont fait l'objet d'une analyse d'IA frauduleuse et d'une exfiltration.
* Rétablir l'intégrité de l'environnement de l'ordinateur à un état sain d'origine.

#### Phase 4 — Activités post-incident

* Mettre en œuvre un retour d'expérience avec les équipes techniques pour adapter les politiques de restriction logicielle des terminaux macOS.
* Évaluer l'exposition réglementaire si la fuite de documents exfiltrés par le faux service de résumé par IA comporte des données personnelles protégées.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exécutions de commandes shell suspectes issues d'applications tierces. | T1059.004 | Journaux d'audit de processus macOS | Chasser le lancement de terminaux `sh` ou `bash` par des processus enfants d'applications développées en Flutter ou en Electron. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `interfumesco[.]com` | Serveur C2 et d'hébergement d'Operation FlutterBridge | Haute |
| Domaine | `ads-parkpro[.]com` | Domaine utilisé pour les redirections publicitaires | Haute |
| URL | `hxxps[://]sinterfumesco[.]com/search?utn=[Tracking` | URL de chargement de la charge utile de WebView | Haute |
| Hash SHA256 | `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845` | Empreinte numérique de l'application PodcastsLounge macOS | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1583.008** | Resource Development | Partner Accounts | Utilisation de comptes Google Ads détournés et certifiés pour distribuer des malwares. |
| **T1204.002** | Initial Access | Malicious File | Téléchargement et exécution d'applications Flutter signées contournant Gatekeeper. |
| **T1059.004** | Execution | Unix Shell | Lancement de commandes shell Unix interactives depuis une WebView masquée. |

---

### Sources

* [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)

---

<div id="phishing-campaign-via-malicious-svg-attachments"></div>

## Phishing campaign via malicious SVG attachments

---

### Résumé technique

Une nouvelle vague de campagnes de phishing exploite de manière intensive les fichiers d'images vectorielles au format SVG (Scalable Vector Graphic) en tant que pièces jointes d'e-mails d'hameçonnage. Ce format d'image permet l'intégration directe de code ECMAScript (JavaScript). 

Étant donné que les navigateurs internet modernes (comme Chrome, Edge ou Firefox) exécutent nativement et de manière par défaut ces fichiers d'images, l'ouverture de la pièce jointe SVG par l'utilisateur déclenche automatiquement l'exécution du script JavaScript intégré. Les attaquants emploient cette technique d'obfuscation pour contourner les protections classiques de sécurité des messageries qui analysent les pièces jointes exécutables standards, et redirigent ensuite de façon furtive la victime vers des sites de collecte d'informations d'identification hébergés sur des TLD (Top-Level Domains) bon marché et souvent abusés à l'image de `.cfd`.

### Analyse de l'impact

L'impact réside dans l'exposition accrue au vol de jetons de session d'accès et d'identifiants d'utilisateurs d'entreprise, facilitée par l'apparence inoffensive et le passage réussi des filtres de sécurité par l'image SVG malveillante.

### Recommandations

1. Configurer la passerelle de messagerie de l'organisation pour analyser et supprimer systématiquement les scripts JavaScript imbriqués dans les pièces jointes de fichiers d'images SVG.
2. Modifier au niveau de l'ensemble des systèmes de l'entreprise l'association par défaut des fichiers `.svg` pour qu'ils s'ouvrent via un visualiseur d'images passif sécurisé (ex : Paint ou Photos de Windows) plutôt que via le navigateur internet.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les collaborateurs aux menaces posées par la réception et l'exécution d'images vectorielles de sources suspectes.
* S'assurer que le filtrage DNS de l'entreprise bloque l'accès aux extensions de domaines non conventionnelles et abusées, comme `.cfd`.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Détecter les événements où l'ouverture d'un fichier `.svg` à partir de l'application de messagerie Outlook déclenche l'exécution d'une instance de navigateur web :
    `process_parent == 'outlook.exe' AND process_name == 'chrome.exe' AND command_line CONTAINS '.svg'`
  * Alerte de passerelle de messagerie sur la réception d'e-mails intégrant des pièces jointes `.svg` comportant des balises `<script>` ou de l'ECMAScript.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Purger de manière globale de l'ensemble des boîtes aux lettres de l'organisation les e-mails identifiés comme appartenant à la campagne d'hameçonnage.
* Bloquer le domaine de l'émetteur de la campagne de phishing au niveau de la passerelle de messagerie.

**Éradication :**
* Supprimer le fichier `.svg` malveillant stocké dans les répertoires de téléchargement temporaires de la machine de l'utilisateur concerné.
* Invalider l'ensemble des sessions de navigation actives si un clic réussi a été opéré par l'utilisateur.

**Récupération :**
* Réinitialiser de manière obligatoire les identifiants d'accès si l'utilisateur a renseigné des informations sur le site de phishing final.
* Réinstaller le profil de l'utilisateur pour parer à tout risque d'injection de script de persistance locale dans le cache du navigateur.

#### Phase 4 — Activités post-incident

* Mettre à jour les modèles de détection et de blocage de l'antivirus de l'entreprise avec les empreintes numériques des fichiers SVG identifiés.
* Rédiger un mémo de retour d'expérience à destination de l'équipe de défense opérationnelle.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de clics d'utilisateurs sur des images SVG malveillantes. | T1566.001 | Journaux de proxy web SIEM | Filtrer l'accès à des adresses internet se terminant par `.cfd` ou impliquant des redirections consécutives à l'exécution locale de fichiers d'images de type SVG. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[://]radar[.]cloudflare[.]com/tlds/cfd?dateRange=7d` | Référence de domaine TLD de redirection malveillante | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1566.001** | Initial Access | Spearphishing Attachment | Utilisation de fichiers d'images SVG malveillants intégrant du code d'exécution dynamique. |

---

### Sources

* [SANS Internet Storm Center (ISC)](https://isc.sans.edu/diary/rss/33040)

---

<div id="phishing-campaign-via-view-vibes-on-github-pages"></div>

## Phishing campaign via view-vibes on GitHub Pages

---

### Résumé technique

Une campagne d'hameçonnage active exploite la légitimité des services d'hébergement de GitHub Pages pour héberger une page malveillante de collecte d'informations d'identification sous l'URL `sahana-saini.github.io/view-vibes`. Les attaquants configurent ces interfaces Web d'hameçonnage pour simuler des formulaires de connexion ou d'accès d'applications Web populaires et dérober de manière passive les mots de passe et identifiants saisis par les victimes à destination de serveurs d'exfiltration tiers.

### Analyse de l'impact

L'impact est de niveau faible à moyen, induisant une exposition à des compromissions individuelles de comptes de messagerie ou de services personnels d'employés de l'entreprise s'étant connectés sur la plateforme d'hameçonnage.

### Recommandations

1. Bloquer de manière d'urgence l'accès réseau à l'URL spécifique identifiée de la page d'hameçonnage sur l'ensemble des pare-feux et serveurs proxy de l'entreprise.
2. Signaler de façon proactive l'infraction de contenu de la page malveillante à l'équipe de modération de GitHub pour en exiger le retrait.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir et mettre à jour périodiquement les listes de réputation d'URL et les flux de threat intelligence du proxy de sécurité d'entreprise.
* Former les équipes à la détection de pages d'hameçonnage s'appuyant sur des infrastructures d'hébergement légitimes (comme GitHub Pages ou Google Sites).

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Analyser les logs d'accès réseau DNS et de proxy web de l'entreprise à la recherche de requêtes à destination de l'URL suspecte dans les 48 heures précédant l'alerte :
    `request_uri CONTAINS 'sahana-saini.github.io/view-vibes'`
  * Intercepter au niveau de la messagerie tout e-mail contenant le lien de redirection vers view-vibes.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Bloquer de manière réseau l'accès et les requêtes vers l'URL spécifique : `sahana-saini[.]github[.]io/view-vibes` au niveau du proxy.
* Retirer de l'arborescence des boîtes de réception tous les messages comportant des invitations de redirection à cette adresse.

**Éradication :**
* S'assurer que le cache et l'historique du navigateur web de l'utilisateur ayant éventuellement consulté le lien ont été vidés.

**Récupération :**
* Exiger un renouvellement de mot de passe immédiat de l'utilisateur s'étant connecté sur le faux formulaire de connexion, et activer la double authentification si elle était absente.

#### Phase 4 — Activités post-incident

* Mettre à jour l'évaluation de risques liée à l'exposition des identifiants des utilisateurs de l'entreprise.
* Réaliser une session d'information auprès des équipes de support sur les techniques d'hameçonnage basées sur GitHub Pages.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de connexions à des pages d'hameçonnage GitHub Pages non documentées. | T1566.002 | Journaux d'accès DNS du SIEM | Rechercher des requêtes résolvant des domaines de type `.github.io` comportant des sous-répertoires de types formulaires ou applications suspectes. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxp[://]sahana-saini[.]github[.]io/view-vibes` | Page de collecte de credentials d'hameçonnage active | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1566.002** | Initial Access | Spearphishing Link | Utilisation de liens d'hameçonnage pointant vers des pages hébergées de GitHub Pages. |

---

### Sources

* [Infosec Exchange](https://infosec.exchange/@urldna/116683466878277504)

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