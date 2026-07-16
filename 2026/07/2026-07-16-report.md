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
  * [TeamPCP et compromission de la chaîne d'approvisionnement npm d'AsyncAPI](#teampcp-asyncapi-npm-supply-chain-compromise)
  * [UAC-0145 Group et campagnes d'hameçonnage en Ukraine](#uac-0145-group-phishing-campaigns-in-ukraine)
  * [Distribution du malware MaaS TELEPUZ via des campagnes ClickFix](#telepuz-maas-clickfix-distribution)
  * [OkoBot et ciblage avancé de portefeuilles de cryptomonnaies](#okobot-cryptocurrency-wallets-targeting)
  * [TuxBot v3 et botnet IoT développé à l'aide d'IA génératives](#tuxbot-v3-iot-botnet-via-llm)
  * [Détournement du CLI de Google Gemini en agent de piratage](#google-gemini-cli-abuse-as-hacking-agent)
  * [Développement d'une machine de vente de failles zero-day via IA](#ai-vulnerability-vending-machine)
  * [Hardening des architectures serverless et des fonctions GCP exposées](#gcp-serverless-hardening-exposed-cloud-functions)
  * [Croissance de la surface d'attaque du malware PolinRider](#polinrider-malware-propagation)
  * [Campagne d'hameçonnage Office 365 sur kuyhaa-me.pw](#office-365-phishing-campaigns)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse de la cybermenace de juillet 2026 met en évidence une transformation majeure des tactiques offensives, caractérisée par l'industrialisation des attaques sur la chaîne d'approvisionnement logicielle et l'exploitation de l'IA générative. L'acteur **TeamPCP** (lignée Miasma) illustre parfaitement cette évolution en détournant l'authentification OIDC de GitHub Actions pour signer de manière légitime des paquets malveillants au sein de l'écosystème npm (notamment via AsyncAPI), contournant ainsi les contrôles traditionnels de détection. 

Parallèlement, l'usage d'outils d'intelligence artificielle par les attaquants accélère la recherche de vulnérabilités et l'automatisation d'exploits de pointe (comme démontré par les concepteurs de TuxBot v3 et les expériences de "vending machines" de zero-days). Cela réduit drastiquement le temps de réaction des équipes défensives, particulièrement dans les secteurs de la finance et des infrastructures d'importance vitale (OIV). 

Sur le plan géopolitique, l'intensification des affrontements cybernétiques étatiques se traduit par des campagnes persistantes du groupe chinois **Daxin** à Taiwan et des activités opportunistes du groupe russe **Center 16** (FSB) visant des routeurs et des infrastructures critiques mondiales à des fins d'espionnage et de pré-positionnement tactique.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **TeamPCP** (Miasma / Shai-Hulud Lineage) | Technologie, Développement logiciel, Services Cloud | Compromission de pipelines CI/CD, extraction de jetons OIDC sur GitHub Actions, publication de paquets npm légitimement signés mais trojanisés. | T1195.001 (Supply Chain Compromise),<br>T1059.003 (JavaScript Execution) | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)<br>[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) |
| **FSB Center 16** (Berserk Bear, Crouching Yeti...) | Télécommunications, Défense, Énergie, Finance, Santé | Balayage de plages IP, identification d'agents SNMP actifs avec configurations par défaut, vol de fichiers de configuration d'équipements réseau (Cisco). | T1505 (Server Software Component),<br>T1046 (Network Service Scanning) | [Security Affairs](https://securityaffairs.com/195448/apt/us-and-allied-governments-recommendations-securing-network-devices-against-russian-apt-groups.html) |
| **Daxin Espionage Group** | Gouvernement, Télécommunications, Transports, Haute technologie | Utilisation de pilotes noyau furtifs (rootkits), détournement passif de trafic réseau, persistance via winlogon (backdoor Stupig). | T1014 (Rootkit),<br>T1547.004 (Winlogon Helper DLL) | [Symantec Threat Hunter](https://www.security.com/threat-intelligence/daxin-returns-stupig) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Russie / Ukraine / USA / Iran / Gaza / Europe** | Relations Internationales et Défense | Contestation multilatérale et asymétrie cybernétique | Enlisement des conflits asymétriques, fragmentation de l'ordre international, cyber-opérations d'influence et d'espionnage contre les institutions multilatérales (CPI). | [IRIS - Pascal Boniface](https://www.iris-france.org/rubio-feu-a-volonte-sur-la-cour-penale-internationale/)<br>[IRIS - Romuald Sciora](https://www.iris-france.org/jusqua-quand-les-empires-accepteront-ils-de-perdre/)<br>[IRIS - Sophie Bessis](https://www.iris-france.org/gaza-indignation-selective-et-credibilite-occidentale-avec-sophie-bessis/) |
| **Chine / Taïwan** | Manufacture High Tech, Gouvernement | Espionnage étatique persistant à long terme | Déploiement ciblé du rootkit noyau Daxin et de la backdoor Stupig dissimulée en disposition clavier pour intercepter les identifiants d'infrastructures taïwanaises. | [Symantec Threat Hunter](https://www.security.com/threat-intelligence/daxin-returns-stupig) |
| **Russie / Global** | Infrastructures critiques, OIV | Espionnage et pré-positionnement étatique | Campagnes offensives coordonnées par le Center 16 du FSB russe visant à cartographier et compromettre des routeurs d'entreprises et d'administrations mondiales. | [Security Affairs](https://securityaffairs.com/195448/apt/us-and-allied-governments-recommendations-securing-network-devices-against-russian-apt-groups.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Suspension de la Phase II de CMMC | Département de la Guerre US (DoW) | 15/07/2026 | USA | 32 CFR Part 170 | Allègement de la charge bureaucratique pour les PME de la Base Industrielle de Défense (DIB) au profit d'une sécurité axée sur la résilience réelle. | [GuidePoint Security](https://www.guidepointsecurity.com/blog/cmmc-phase-ii-suspension-risk-based-cybersecurity/) |
| Risques Systémiques des FAIMs | Comité Européen du Risque Systémique (ESRB) | 15/07/2026 | Europe | ESRB/2026/3 | Alertes majeures concernant les risques cybernétiques globaux induits par l'automatisation d'attaques par des modèles d'IA de frontière. | [European Lex](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=OJ:C_202603795) |
| Contrôles Export IA Claude Fable | Département du Commerce US | 15/07/2026 | USA | N/A | Application de contrôles d'exportations stricts sur le modèle d'IA Claude Fable suite à la détection de capacités offensives de recherche de failles. | [Recorded Future](https://www.recordedfuture.com/blog/the-shift-new-era-ai) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Multi-secteurs (Industrie, Énergie, Commerce) | Fluke, Goose Creek, Kudankulam, Nayax, Partnered Health | Noms, adresses, téléphones, historiques de commandes, documents de conception d'ingénierie et plans d'infrastructures industrielles. | +7,4 millions de comptes | [Have I Been Pwned - Fluke](https://haveibeenpwned.com/Breach/Fluke)<br>[Have I Been Pwned - Goose Creek](https://haveibeenpwned.com/Breach/GooseCreek)<br>[DataBreaches.net - Kudankulam](https://databreaches.net/2026/07/15/files-relating-to-indias-largest-nuclear-power-plant-kudankulam-exposed-in-data-breach/)<br>[DataBreaches.net - Nayax](https://databreaches.net/2026/07/15/nayax-updates-its-incident-status-states-it-wont-pay-any-extortion demand/) |
| Gouvernemental / Secours | Calgary 911 (Canada) | Données d'appels d'urgence et dossiers personnels de citoyens (abus de confiance par un agent interne). | Non spécifié | [DataBreaches.net](https://databreaches.net/2026/07/15/calgary-911-employee-charged-with-breach-of-trust/?pk_campaign=feed&pk_kwd=calgary-911-employee-charged-with-breach-of-trust) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-58644 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2026-15409 | TRUE  | Active    | 6.5 | 10.0  | (1,1,6.5,10.0)|
| 3 | CVE-2026-15410 | TRUE  | Active    | 6.0 | N/A→0 | (1,1,6.0,0)   |
| 4 | CVE-2026-56164 | TRUE  | Active    | 6.0 | N/A→0 | (1,1,6.0,0)   |
| 5 | Zoom Account TO| FALSE | Active    | 2.5 | N/A→0 | (0,1,2.5,0)   |
| 6 | ZDI-26-441     | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 7 | CVE-2026-54458 | FALSE | Théorique | 1.5 | 9.6   | (0,0,1.5,9.6) |
| 8 | CVE-2026-55652 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 9 | CVE-2026-55576 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 10| CVE-2026-55445 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 11| ZDI-26-444     | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 12| ZDI-26-438     | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 13| LegacyHive     | FALSE | PoC Public| 1.5 | N/A→0 | (0,0,1.5,0)   |
| 14| CVE-2026-1609  | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 15| CVE-2026-52893 | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 16| ZDI-26-443     | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 17| ZDI-26-442     | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 18| ZDI-26-439     | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-58644** | 9.8 | N/A | **TRUE** | **7.0** | Microsoft SharePoint Server | Deserialization of untrusted data | RCE | Active | Appliquer la mise à jour cumulative de juillet 2026 et isoler le serveur. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-admins-to-patch-actively-exploited-sharepoint-flaws/) |
| **CVE-2026-15409** | 10.0 | N/A | **TRUE** | **6.5** | SonicWall SMA 1000 Series | Server-Side Request Forgery | SSRF (Critique) | Active | Installer immédiatement le hotfix de SonicWall ; restreindre l'accès à l'interface d'administration. | [CERT-FR ALE-006](https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-006/)<br>[SonicWall PSIRT](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008) |
| **CVE-2026-15410** | N/A | N/A | **TRUE** | **6.0** | SonicWall SMA 1000 Series | Post-Authentication Code Injection | RCE | Active | Mettre à niveau le microcode du boîtier VPN de manière prioritaire. | [Security Affairs](https://securityaffairs.com/195383/security-u-s-cisa-adds-sonicwall-and-microsoft-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-56164** | N/A | N/A | **TRUE** | **6.0** | Microsoft SharePoint Server | Remote Code Execution | RCE | Active | Déployer le correctif Microsoft de juillet 2026 et activer AMSI. | [Field Effect](https://fieldeffect.com/blog/microsoft-patch-addresses-sharepoint-vulnerabilities) |
| **Zoom Account TO** | N/A | N/A | FALSE | **2.5** | Client Zoom Windows et SDK | Session Management Flaw | Auth Bypass | Active | Appliquer d'urgence la dernière mise à jour de Zoom Windows et imposer le SSO/MFA. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/zoom-warns-of-critical-account-takeover-vulnerability/) |
| **ZDI-26-441** | N/A | N/A | FALSE | **2.0** | dnsmasq | Heap-based Buffer Overflow | RCE | Théorique | Mettre à jour vers le dernier correctif fourni par la distribution Linux. | [Zero Day Initiative](http://www.zerodayinitiative.com/advisories/ZDI-26-441/) |
| **CVE-2026-54458** | 9.6 | N/A | FALSE | **1.5** | WWBN AVideo | DOM-based XSS (via YPTSocket) | Auth Bypass | Théorique | Désactiver le plugin YPTSocket et passer à la version AVideo 29.0. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-54458) |
| **CVE-2026-55652** | N/A | N/A | FALSE | **1.5** | Wekan | HTTP Header IP Spoofing (getRequestIp) | Auth Bypass | Théorique | Installer immédiatement Wekan v9.46. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-55652) |
| **CVE-2026-55576** | N/A | N/A | FALSE | **1.5** | MaaAssistantArknights | GitHub Actions Input Injection | RCE | Théorique | Éviter d'intégrer des variables d'événements GitHub non assainies dans les scripts. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-55576) |
| **CVE-2026-55445** | N/A | N/A | FALSE | **1.5** | Qinglong Platform | Incomplete Auth Bypass Fix | Auth Bypass | Théorique | Mettre à niveau Qinglong vers la version stable 2.20.1. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-55445) |
| **ZDI-26-444** | N/A | N/A | FALSE | **1.5** | 7-Zip | Heap-based Buffer Overflow (XZ parsing) | RCE | Théorique | Mettre à jour l'application 7-Zip vers sa version la plus récente. | [Zero Day Initiative](http://www.zerodayinitiative.com/advisories/ZDI-26-444/) |
| **ZDI-26-438** | N/A | N/A | FALSE | **1.5** | Rockwell Arena Simulation | Out-of-bounds Write (DOE parsing) | RCE | Théorique | Mettre à jour Rockwell Arena Simulation et restreindre l'ouverture de projets suspects. | [Zero Day Initiative](http://www.zerodayinitiative.com/advisories/ZDI-26-438/) |
| **LegacyHive** | N/A | N/A | FALSE | **1.5** | Microsoft Windows (ProfSvc) | Local Privilege Escalation | LPE | PoC Public | Auditer les appels au service ProfSvc et restreindre les privilèges d'administration locaux. | [Security Affairs](https://securityaffairs.com/195418/hacking/chaotic-eclipse-unveils-legacyhive-exploit-affecting-fully-patched-windows-systems.html) |
| **CVE-2026-1609** | N/A | N/A | FALSE | **1.0** | Keycloak | Exp. JWT Authorization Grant | Auth Bypass | Théorique | Désactiver la fonction expérimentale de jetons de tiers Keycloak ou appliquer le correctif. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-1609) |
| **CVE-2026-52893** | N/A | N/A | FALSE | **1.0** | Wekan | Automatic OIDC Account Merge | Auth Bypass | Théorique | Configurer le fournisseur d'identité OIDC pour requérir validation de l'email ; mettre à jour v9.32. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-52893) |
| **ZDI-26-443** | N/A | N/A | FALSE | **1.0** | Pilote vmwgfx Noyau Linux | Heap Overflow | LPE | Théorique | Mettre à jour le noyau Linux et désactiver les pilotes graphiques superflus. | [Zero Day Initiative](http://www.zerodayinitiative.com/advisories/ZDI-26-443/) |
| **ZDI-26-442** | N/A | N/A | FALSE | **1.0** | Protocole CAN ISO-TP Linux | Race Condition | LPE | Théorique | Désactiver le protocole réseau ISO-TP du noyau si non essentiel. | [Zero Day Initiative](http://www.zerodayinitiative.com/advisories/ZDI-26-442/) |
| **ZDI-26-439** | N/A | N/A | FALSE | **1.0** | Pilote pcid64 Fuji Electric Tellus | Insecure Driver Exposed Method | LPE | Théorique | Mettre à niveau le logiciel Fuji Electric Tellus selon l'avis ICSA-26-132-01. | [Zero Day Initiative](http://www.zerodayinitiative.com/advisories/ZDI-26-439/) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Paquets npm AsyncAPI infectés par un voleur de clés | TeamPCP + AsyncAPI npm supply chain compromise | Attaque supply-chain d'envergure ciblant des dépendances de confiance d'écosystèmes DevOps très populaires. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/-asyncapi-npm-packages-infected-with-credential-stealing-malware/) |
| Vecteurs de compromission initiale d'UAC-0145 (juillet 2026) | UAC-0145 Group + Phishing campaigns in Ukraine | Activité étatique d'un groupe d'espionnage exploitant des mécanismes de faux outils de mise à jour pour cibler l'Ukraine. | [CERT-UA](https://cert.gov.ua/article/6318437) |
| TELEPUZ: Un malware modulaire MaaS diffusé via ClickFix | TELEPUZ MaaS + ClickFix distribution | Évolution des techniques ClickFix (ingénierie sociale via copier-coller) propageant une nouvelle souche furtive. | [Elastic Security Labs](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix) |
| OkoBot : Un nouveau framework malveillant sophistiqué | OkoBot + Cryptocurrency wallets targeting | Attaque criminelle ciblant directement des "cold wallets" physiques via l'altération de la mémoire de l'OS. | [Kaspersky Securelist](https://securelist.com/okobot-framework-targets-cryptocurrency-wallets/120660/) |
| TuxBot v3 : Dans les coulisses d'un framework développé via LLM | TuxBot v3 + IoT botnet via LLM | Démonstration concrète d'une menace de botnet programmée à l'aide d'IA de génération de code. | [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/) |
| Détournement du CLI Google Gemini en agent de piratage | Google Gemini CLI + Abuse as hacking agent | Détournement innovant des configurations d'outils CLI officiels d'IA pour piloter des botnets. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-gemini-cli-abused-as-a-hacking-agent-malware-botnet-operator/) |
| Machine de vente de failles : jetons d'IA en entrée, zero-days en sortie | AI vulnerability vending machine | Preuve de concept d'une automatisation complète d'attaques zero-day orchestrée de bout en bout par l'IA. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/we-built-a-vulnerability-vending-machine-ai-tokens-in-zero-days-out/) |
| Risques et durcissement des fonctions Cloud publiques exposées | GCP Serverless + Hardening exposed Cloud Functions | Vulnérabilités de premier plan affectant les infrastructures cloud et l'évaluation du "Vibe Coding" via LLM. | [Google Cloud Blog / Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/exposed-cloud-functions-harden/) |
| La surface d'attaque de PolinRider multipliée par 6,5 | PolinRider + Malware propagation | Recrudescence majeure et propagation de charges malveillantes multi-systèmes en expansion continue. | [Open Source Malware Blog](https://opensourcemalware.com/blog/polinrider-blast-radius-grows) |
| Hameçonnage Office suspecté sur kuyhaa-me.pw | Office 365 + Phishing campaigns | Campagne active de capture de mots de passe d'entreprises ciblant les applications d'entreprise hébergées. | [URLDNA Exchange](https://infosec.exchange/@urldna/116926828272163279) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| SANS ISC Stormcast du 15 juillet 2026 | Contenu de podcast d'actualités générales non structuré comme un incident de sécurité ou analyse de menace spécifique. | [SANS ISC](https://isc.sans.edu/diary/rss/33158) |
| Mise à jour récente du DShield SIEM | Bulletin technique de mise à jour fonctionnelle de capteur défensif, sans rapport d'incident ou de menace directe. | [SANS ISC](https://isc.sans.edu/diary/rss/33156) |
| Microsoft : Extinction de PC Dell suite à des mises à jour Windows | Bug de compatibilité matérielle et régression logicielle ne constituant pas un événement cyber-offensif ou de sécurité. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft-microsoft-some-dell-devices-shut-down-after-windows-update/) |
| Ajout Shodan : ASN AS3320 à Prien am Chiemsee | Notification brute d'exposition de services en ligne Shodan sans analyse de menace contextualisée ni incident actif. | [Shodan Safari Mastodon](https://infosec.exchange/@shodansafari/116926946331886383) |
| Recommandations d'hygiène de sécurité de base pour macOS | Guide de bonnes pratiques générales de sécurité ne traitant d'aucune menace émergente ou intrusion avérée. | [Grumpy Bozo Mastodon](https://toad.social/@grumpybozo/116926550702909383) |
| Inculpation d'un agent de Calgary 911 | Article de presse traitant principalement des aspects judiciaires et d'infractions individuelles sans détails techniques cyber-offensifs. | [DataBreaches.net](https://databreaches.net/2026/07/15/calgary-911-employee-charged-with-breach-of-trust/?pk_campaign=feed&pk_kwd=calgary-911-employee-charged-with-breach-of-trust) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

<div id="teampcp-asyncapi-npm-supply-chain-compromise"></div>

## TeamPCP et compromission de la chaîne d'approvisionnement npm d'AsyncAPI

---

### Résumé technique

Au cours de l'année 2025 et jusqu'à la mi-2026, l'acteur de menace **TeamPCP** (également désigné comme la lignée Miasma / Shai-Hulud) a opéré des vagues d'attaques supply chain automatisées ciblant l'écosystème npm, et plus particulièrement les paquets de l'organisation de confiance **AsyncAPI** (comme `@asyncapi/specs` et `@asyncapi/generator`). 

L'attaque s'est matérialisée par l'exploitation d'une vulnérabilité de type configuration lâche du workflow `pull_request_target` au sein de GitHub Actions. Les attaquants ont soumis des Pull Requests malveillantes depuis des dépôts forkes pour forcer le runner GitHub à s'exécuter dans le contexte du dépôt parent, lui permettant d'exfiltrer le jeton de sécurité `asyncapi-bot` configuré avec des droits de publication npm étendus. 

Muni de ces accès légitimes, l'acteur a téléversé des paquets npm officiels trojanisés intégrant le chargeur malveillant **Miasma**. Ce code s'exécute de manière furtive au moment du chargement du module (`require-time` / `import-time`), ce qui lui permet de s'affranchir et de contourner les protections classiques de type `--ignore-scripts` qui bloquent uniquement les scripts de phase d'installation (`postinstall`). Miasma utilise des passerelles IPFS (InterPlanetary File System) et des appels de contrats RPC Ethereum pour récupérer la localisation dynamique de son infrastructure de commande et de contrôle (C2), d'où il télécharge un extracteur de secrets d'environnement et de jetons d'accès cloud (AWS/GCP).

---

### Analyse de l'impact

*   **Impact opérationnel** : Vol de secrets d'infrastructure de builds, de clés d'API cloud (AWS/GCP) et de jetons de déploiement npm, provoquant des compromissions secondaires massives au sein des pipelines de livraison (CI/CD) des entreprises clientes.
*   **Complexité** : Très élevée. Le contournement de la protection `--ignore-scripts` via l'exécution au chargement, conjugué à la signature cryptographique OIDC valide de GitHub Actions, rend la détection via les outils de gestion d'inventaire de dépendances (SCA) inefficace.
*   **Rayon d'action** : Potentiellement plus de 2 millions de développeurs et d'infrastructures de build exposés à chaque déploiement de mise à jour des paquets corrompus.

---

### Recommandations

1.  Proscrire l'usage combiné de `pull_request_target` avec des checkouts de branches distantes non évaluées au sein de GitHub Actions.
2.  Mettre en place des mécanismes de contrôle de conformité stricts interdisant aux pipelines CI/CD d'exécuter des flux sortants non authentifiés vers des adresses IP externes ou des passerelles IPFS publiques.
3.  Utiliser un registre de paquets local privé et valider les attestations de provenance de builds SLSA à l'aide de l'outil `slsa-verifier`.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Activer la centralisation des logs d'audit des workflows de l'organisation GitHub.
*   Configurer l'EDR des serveurs d'intégration continue pour enregistrer la télémétrie des exécutions du binaire Node.js et des processus enfants lancés depuis les runners.
*   Vérifier l'existence d'un processus automatisé de révocation et de rotation rapide des secrets d'organisation (GITHUB_TOKEN, NPM_TOKEN).

#### Phase 2 — Détection et analyse

*   **Règle de détection EDR** (Recherche d'exécution de commande d'exfiltration) :
    ```
    ParentImage == "*node*" OR ParentImage == "*bun*"
    CommandLine == "*gh auth token*" OR CommandLine == "*.npmrc*"
    ```
*   **Règle Sigma (Query SIEM)** :
    ```yaml
    title: Node.js Executing Suspicious CLI Commands for Secret Retrieval
    status: experimental
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            ParentImage|contains: 'node'
            CommandLine|contains:
                - 'gh auth token'
                - '.npmrc'
                - 'env'
        condition: selection
        level: high
    ```
*   Analyser les logs de pare-feu et les connexions DNS à la recherche de requêtes dirigées vers des passerelles IPFS suspectes ou des endpoints Ethereum RPC.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Désactiver immédiatement le jeton d'accès GitHub compromis (révocation de `asyncapi-bot` ou des secrets associés).
*   Isoler logiquement le runner de compilation suspecté d'avoir fait l'objet de l'injection.
*   Bloquer les passerelles IPFS connues sur vos serveurs proxy d'entreprise.

**Éradication :**
*   Supprimer les caches locaux de npm et forcer le downgrade ou la réinstallation de versions saines (ex: antérieures ou correctives révisées par l'éditeur).
*   Identifier et purger les fichiers de configuration `.miasma` ou scripts `sync.js` dans les dossiers temporaires des runners.

**Récupération :**
*   Régénérer et tourner l'intégralité des identifiants cloud et de déploiement exposés au sein du fichier d'environnement du pipeline.
*   Valider l'intégrité de toutes les compilations logicielles produites pendant la période de suspicion avant d'autoriser leur mise en production.

#### Phase 4 — Activités post-incident

*   Effectuer une notification NIS2 aux autorités sous 24 heures en raison du risque systémique engendré par la corruption de la chaîne d'approvisionnement.
*   Mener un retour d'expérience (REX) avec l'équipe de sécurité DevOps pour durcir les politiques d'isolation réseau des runners éphémères.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exfiltration réseau de jetons via requêtes HTTP directes des runners vers IPFS | T1195.001 | Logs de Proxy / DNS | Rechercher les résolutions DNS de sous-domaines contenant `ipfs` ou `publicnode` associés à des flux provenant de serveurs de builds. |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `85.137.53[.]71` | Serveur de commande et contrôle (C2) de Miasma | Haute |
| Domaine | `ipfs[.]io` | Passerelle de distribution réseau IPFS utilisée par le malware | Moyenne |
| Domaine | `cloudflare-ipfs[.]com` | Passerelle secondaire IPFS | Moyenne |
| Domaine | `ethereum-rpc.publicnode[.]com` | Endpoint RPC de recherche d'infrastructure dynamique | Moyenne |
| Hash SHA256 | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` | Fichier JavaScript sync.js trojanisé | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.001 | Initial Access | Supply Chain Compromise: Malware Dependencies | Injection d'un injecteur JavaScript malveillant au chargement du module npm AsyncAPI. |
| T1059.003 | Execution | Command and Scripting Interpreter: JavaScript | Exécution automatisée de code JavaScript Miasma via Node.js dans l'environnement du développeur. |
| T1560 | Collection | Archive Collected Data | Chiffrement et packaging des secrets environnementaux d'intégration avant envoi sur IPFS. |

---

### Sources

*   [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
*   [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
*   [BleepingComputer](https://www.bleepingcomputer.com/news/security/-asyncapi-npm-packages-infected-with-credential-stealing-malware/)
*   [Security Affairs](https://securityaffairs.com/195395/security/asyncapi-npm-supply-chain-attack-malware-injected-into-packages-with-2-million-weekly-downloads.html)

---

<div id="uac-0145-group-phishing-campaigns-in-ukraine"></div>

## UAC-0145 Group et campagnes d'hameçonnage en Ukraine

---

### Résumé technique

L'acteur de menace étatique **UAC-0145** a mené de vastes campagnes de cyberespionnage ciblant les administrations publiques ukrainiennes. Le vecteur initial d'intrusion repose sur des e-mails d'hameçonnage hautement contextualisés usurpant les communications officielles de Microsoft Office et invitant les destinataires à appliquer d'urgence des mises à jour correctives critiques de sécurité Windows et Office. 

Le lien de redirection mène les cibles vers des serveurs contrôlés par l'attaquant qui simulent l'interface légitime d'un portail Microsoft, d'où est téléchargée une charge utile sous la forme d'un exécutable malveillant d'apparence inoffensive (faux agent d'installation d'update). Une fois exécuté par l'utilisateur, ce programme installe une porte dérobée persistante sur le poste de travail de la victime permettant de contourner les protections locales, d'intercepter les saisies clavier et d'exfiltrer les fichiers gouvernementaux hautement sensibles.

---

### Analyse de l'impact

*   **Impact opérationnel** : Espionnage gouvernemental, compromission d'informations diplomatiques et militaires critiques en Ukraine, et exfiltration à long terme de documents secrets.
*   **Sophistication** : Moyenne à élevée. Repose fortement sur la qualité de l'ingénierie sociale (usurpation Microsoft) et l'usurpation d'identités institutionnelles pour forcer l'exécution par l'utilisateur.

---

### Recommandations

1.  Déployer des politiques restrictives interdisant aux collaborateurs d'exécuter des fichiers exécutables téléchargés depuis l'extérieur des répertoires de confiance de l'entreprise.
2.  Sensibiliser les utilisateurs gouvernementaux aux techniques d'hameçonnage axées sur les demandes impromptues de correctifs de sécurité de leur système d'exploitation.

---

### Playbook de réponse à incident

#### Phase 1 — Preparation

*   Vérifier le paramétrage de la messagerie pour bloquer les e-mails entrants provenant de domaines suspects nouvellement enregistrés.
*   S'assurer que les agents EDR locaux bloquent le lancement de commandes système par des navigateurs web ou des clients de messagerie.

#### Phase 2 — Détection et analyse

*   Identifier les résolutions DNS émises par le parc vers les noms de domaine liés à cette campagne.
*   **Requête de Threat Hunting EDR** :
    ```
    ProcessName == "cmd.exe" OR ProcessName == "powershell.exe"
    ParentProcessName IN ("outlook.exe", "msedge.exe", "chrome.exe")
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Isoler immédiatement les hôtes ayant communiqué avec les adresses IP d'UAC-0145 ou résolu les noms de domaine malveillants.
*   Couper logiquement les comptes d'accès Active Directory associés aux machines compromises.

**Éradication :**
*   Supprimer les faux installateurs de correctifs du répertoire temporaire de l'utilisateur.
*   Nettoyer les ruches de registre Windows altérées pour la persistance de l'agent.

**Récupération :**
*   Réinstaller l'OS complet du poste gouvernemental touché pour garantir l'élimination de charges secondaires.
*   Réinitialiser les jetons et identifiants de messagerie des victimes de la campagne.

#### Phase 4 — Activités post-incident

*   Informer le CERT-UA afin de centraliser et d'alimenter la base d'indicateurs d'attaque au niveau national.
*   Mettre à jour les règles de détection YARA de la passerelle de messagerie.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détecter de faux packages de mise à jour s'exécutant dans les profils locaux | T1566 | Journaux d'événements de processus Windows | Rechercher des processus s'exécutant depuis `%TEMP%` avec des métadonnées de description falsifiées (ex: "Microsoft Update Utility"). |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `365softupdate[.]com` | Serveur de phishing et de livraison de payload | Haute |
| Domaine | `softupdater[.]org` | Serveur secondaire de mise à jour simulée | Haute |
| Hash SHA256 | `0abaae3054d6dc5bee1f17684df98bf427e5c73eb3a0febb123f9ce670dbde78` | Exécutable Windows malveillant (faux installeur) | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566 | Initial Access | Phishing: Spearphishing Link | Envoi d'e-mails malveillants usurpant Microsoft pour inciter au téléchargement de faux correctifs. |

---

### Sources

*   [CERT-UA](https://cert.gov.ua/article/6318437)

---

<div id="telepuz-maas-clickfix-distribution"></div>

## Distribution du malware MaaS TELEPUZ via des campagnes ClickFix

---

### Résumé technique

La souche malveillante modulaire **TELEPUZ** (diffusée selon un modèle de *Malware-as-a-Service*) est activement distribuée via la technique d'ingénierie sociale sophistiquée **ClickFix**. Les utilisateurs accèdent à des sites web compromis ou des faux portails d'assistance technique affichant un message d'erreur d'affichage de page. L'interface propose alors de corriger le problème en cliquant sur un bouton qui copie automatiquement une instruction malveillante dans le presse-papiers de Windows, puis enjoint l'utilisateur à exécuter un terminal d'invite de commande (CMD / PowerShell) et à coller le code (`Ctrl+V` puis `Entrée`). 

Une fois l'instruction PowerShell exécutée, elle télécharge et déploie le malware TELEPUZ. Écrit en C, ce programme utilise une technique de contournement avancée consistant à cloner la bibliothèque système `ntdll.dll` directement en mémoire virtuelle pour effectuer des appels système (syscalls) indirects non surveillés par les agents EDR locaux. De plus, il intègre des routines de désactivation de l'interface d'analyse AMSI et du traçage ETW (Event Tracing for Windows), avant de déployer un module de type Vidar Stealer pour collecter les identifiants, sessions web et secrets financiers stockés localement.

---

### Analyse de l'impact

*   **Impact opérationnel** : Vol de cookies de session d'administration, de secrets bancaires et de portefeuilles de crypto-actifs, débouchant sur des contournements de MFA par vol de jetons de session.
*   **Sophistication** : Élevée. La technique ClickFix élimine le besoin d'exploiter une vulnérabilité logicielle en exploitant l'interaction humaine forcée. La furtivité technique de TELEPUZ (clonage ntdll) neutralise de nombreux pare-feux et antivirus de nouvelle génération (NGAV).

---

### Recommandations

1.  Déployer des stratégies de restriction Windows bloquant l'exécution de commandes système PowerShell ou CMD directement initiées par l'utilisateur lorsque des requêtes réseau sortantes inhabituelles y sont liées.
2.  Activer la protection de l'intégrité de la mémoire et restreindre l'accès à la modification d'AMSI au sein de Windows.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Mettre en place des règles au niveau EDR pour surveiller et alerter en cas de copie d'instructions de scripts complexes dans le presse-papiers suivi de l'ouverture instantanée de PowerShell.
*   S'assurer que les flux d'exécution réseau de PowerShell sont documentés et audités.

#### Phase 2 — Détection et analyse

*   Analyser les processus locaux pour repérer le lancement de `computerdefault.exe` ou d'exécutions suspectes de `rundll32.exe`.
*   **Requête PowerShell de Threat Hunting** (recherche d'appel système indirect et instabilité AMSI) :
    ```powershell
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -like "*AmsiPatch*" -or $_.Message -like "*clip*"}
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Couper instantanément les liaisons réseau de la machine compromise vers Internet.
*   Révoquer et invalider toutes les sessions actives (cookies) associées aux comptes s'étant connectés sur l'hôte depuis les dernières 48 heures.

**Éradication :**
*   Tuer le processus d'exécution `rundll32.exe` hébergeant la bibliothèque injectée de TELEPUZ.
*   Supprimer les fichiers temporaires stockés sous `%TEMP%` ou `%AppData%` associés à l'artefact.

**Récupération :**
*   Scanner l'intégralité du parc pour s'assurer de l'absence du mutex de persistance `cfgmgr_mtx`.
*   Rétablir l'image saine de la machine.

#### Phase 4 — Activités post-incident

*   Actualiser la base de signatures d'intrusions locales pour bloquer le domaine de distribution `cal.snehamumbai[.]org`.
*   Ajuster la sensibilisation des collaborateurs à l'ingénierie sociale "ClickFix".

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de manipulation du presse-papiers suivie d'exécution PowerShell | T1204.001 | Télémétrie Sysmon | Surveiller les événements de création de processus PowerShell dont les arguments contiennent des commandes d'exécution encodées de type Base64 ou des patterns d'appels réseau `DownloadString`. |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Hash SHA256 | `03fa348b70819296c958c842e7646b3b7efe5fa217ed5098143003c47995a746` | Exécutable principal TELEPUZ | Haute |
| Domaine | `cal.joycedoula[.]com[.]br` | Serveur relais d'infection ClickFix | Haute |
| Domaine | `cal.snehamumbai[.]org` | Serveur d'exfiltration des données volées | Haute |
| Nom de fichier | `computerdefault.exe` | Fichier d'exploitation de contournement d'UAC | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1204.001 | Execution | User Execution: Malicious Link | Manipulation de l'utilisateur pour l'amener à copier et exécuter manuellement une charge malveillante. |
| T1548.002 | Privilege Escalation | Bypass User Account Control | Utilisation de mécanismes de contournement UAC natifs de Windows pour exécuter le malware avec hauts privilèges. |

---

### Sources

*   [Elastic Security Labs](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix)

---

<div id="okobot-cryptocurrency-wallets-targeting"></div>

## OkoBot et ciblage avancé de portefeuilles de cryptomonnaies

---

### Résumé technique

Le framework malveillant **OkoBot** est distribué activement par des acteurs russophones à l'aide de faux portails de documentation de cold wallets (portefeuilles matériels de cryptomonnaie). Le programme déploie des binaires d'injection tels que `extl.exe` ou `HDUtil.exe` et lance un processus de persistance dissimulé sous un processus Microsoft légitime (`winver.exe`). 

Le cœur technique d'OkoBot consiste à injecter du code malveillant en mémoire au sein des processus des applications officielles **Trezor Suite** et **Ledger Live**. En détournant les fonctions d'appels systèmes (hooks sur `SspiCli!LsaLogonUser` ou `Advapi32!CredUnprotectA`), OkoBot intercepte l'affichage normal de ces portefeuilles matériels pour injecter de fausses pages d'erreur de synchronisation, qui invitent l'utilisateur à saisir sa phrase de récupération physique (seed phrase) de 12 ou 24 mots. Les informations saisies sont ensuite chiffrées puis transmises via un canal SSH secret vers l'infrastructure des attaquants.

---

### Analyse de l'impact

*   **Impact opérationnel** : Vol de crypto-actifs par extraction des phrases de récupération, entraînant des pertes financières immédiates et irréversibles pour les victimes d'organisations financières.
*   **Sophistication** : Élevée. L'altération à chaud de la mémoire d'applications réputées ultra-sécurisées comme Ledger ou Trezor permet d'abuser de la confiance de l'utilisateur.

---

### Recommandations

1.  Rappeler de façon stricte aux collaborateurs qu'une phrase de récupération physique (seed phrase) ne doit **jamais** être saisie sur une interface logicielle ou un clavier d'ordinateur.
2.  Auditer et bloquer les applications de crypto-monnaies non nécessaires au contexte métier sur les parcs informatiques professionnels.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Mettre en place des signatures d'intégrité de code au niveau EDR pour détecter les tentatives d'écriture ou d'injection de mémoire dans les processus applicatifs Ledger et Trezor.
*   Ajuster la télémétrie Windows pour auditer l'enregistrement de processus winver.exe exécutés en mode débogage.

#### Phase 2 — Détection et analyse

*   Détecter la présence du script d'injection `TookPS` ou l'exécution de `extl.exe`.
*   **Requête de détection EDR** (recherche d'écriture mémoire inter-processus) :
    ```
    SourceProcessName == "winver.exe" OR SourceProcessName == "extl.exe"
    TargetProcessName IN ("Trezor Suite.exe", "Ledger Live.exe")
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Isoler immédiatement l'ordinateur de la victime du réseau internet pour interrompre l'exfiltration via SSH.
*   Transférer de manière urgente les fonds des comptes potentiellement compromis vers de nouveaux cold wallets générés hors ligne.

**Éradication :**
*   Supprimer les fichiers d'OkoBot stockés dans les répertoires et nettoyer la clé de registre associée.
*   Purger les extensions de navigateurs Chrome non répertoriées ou installées de force.

**Récupération :**
*   Restaurer la machine à partir d'une image d'installation propre pour éliminer toute DLL persistante dans `System32`.

#### Phase 4 — Activités post-incident

*   Mener un retour d'expérience avec les traders ou équipes financières de l'organisation pour réviser les politiques de sécurité liées aux cold wallets.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détecter le contournement d'UAC opéré par OkoBot via msconfig.exe | T1548.002 | Logs de processus Windows | Rechercher le processus `msconfig.exe` exécutant des scripts non signés ou initiant l'outil d'injection `extl.exe`. |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `moonsand[.]store` | Serveur de commande et contrôle (C2) d'OkoBot | Haute |
| Domaine | `coffeesaloon[.]online` | Serveur secondaire d'exfiltration | Haute |
| Hash MD5 | `7306885BB4C98F2A9F056104CF092BC9` | Bibliothèque injecteur OkoBot | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1548.002 | Privilege Escalation | Bypass User Account Control | Utilisation de contournement d'UAC via msconfig pour exécuter l'injecteur avec hauts privilèges. |
| T1132 | Command and Control | Data Encoding | Chiffrement et encapsulation du trafic d'exfiltration vers moonsand.store. |

---

### Sources

*   [Kaspersky Securelist](https://securelist.com/okobot-framework-targets-cryptocurrency-wallets/120660/)

---

<div id="tuxbot-v3-iot-botnet-via-llm"></div>

## TuxBot v3 et botnet IoT développé à l'aide d'IA génératives

---

### Résumé technique

La souche **TuxBot v3** représente l'évolution d'un framework d'infection de type botnet d'origine iranienne visant les objets connectés (IoT). L'analyse de son code source met en évidence l'utilisation massive de grands modèles de langage (LLM) par ses concepteurs pour générer les routines de compilation croisée (multi-architecture MIPS, ARM, x86) et d'automatisation des attaques par déni de service distribué (DDoS). 

Cependant, cette conception automatisée a également introduit des vulnérabilités de logique notables (hallucinations d'IA) dans le mécanisme de chiffrement du botnet, limitant la portée de ses communications de commande et de contrôle (C2). Le vecteur d'attaque de TuxBot v3 repose sur la recherche active de terminaux IoT exposant publiquement les ports Telnet ou SSH, puis sur l'injection de scripts de force brute utilisant la liste d'identifiants par défaut du fabricant ("bannière Akiru"). Une fois en mémoire, il lance des campagnes massives de déni de service distribué (DDoS) à la demande.

---

### Analyse de l'impact

*   **Impact opérationnel** : Ralliement d'équipements IoT d'entreprises dans un botnet offensif, saturation de bandes passantes et indisponibilité d'infrastructures internet tierces.
*   **Sophistication** : Faible à moyenne. Malgré l'utilisation de l'IA pour générer le code, les faiblesses logiques et les bugs structurels du chiffrement réduisent l'efficacité réelle du botnet.

---

### Recommandations

1.  Désactiver impérativement les protocoles Telnet et SSH non chiffrés exposés sur l'Internet public pour l'ensemble des caméras, routeurs ou capteurs IoT de l'organisation.
2.  Modifier immédiatement tous les identifiants d'usine par défaut lors de la mise en service de matériels IoT.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Mettre en œuvre un inventaire régulier des dispositifs IoT rattachés au réseau de l'entreprise.
*   Configurer des pare-feux pour interdire les requêtes d'administration externe vers les interfaces de gestion des objets connectés.

#### Phase 2 — Détection et analyse

*   Surveiller les hausses soudaines de trafic ICMP ou de requêtes réseau répétitives initiées par un dispositif IoT de l'organisation.
*   **Règle de détection de flux réseau** (découverte d'activité de scan Telnet) :
    ```
    DestinationPort == 23 OR DestinationPort == 2222
    RequestsCount > 100 within 1 minute
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Isoler logiquement le segment de réseau hébergeant le dispositif IoT compromis.
*   Bloquer l'adresse IP de destination `185.10.68[.]127` au niveau du routeur.

**Éradication :**
*   Redémarrer physiquement ou logiciellement l'appareil IoT infecté pour effacer la charge TuxBot de la mémoire volatile (RAM).
*   Mettre à jour immédiatement les identifiants d'accès d'administration de l'équipement connecté.

**Récupération :**
*   Déployer la dernière version du firmware du fabricant contenant des correctifs de sécurité applicatives.

#### Phase 4 — Activités post-incident

*   Vérifier que les modifications de mots de passe sont appliquées de façon globale sur l'ensemble du réseau IoT pour prévenir les réinfections automatiques par le ver.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identifier des terminaux IoT effectuant du scanning externe proactif | T1110.001 | Logs de connexions de pare-feu | Rechercher des pics de connexions réseau sortantes vers des adresses externes suspectes initiés exclusivement par des adresses IP d'objets connectés du parc. |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `185.10.68[.]127` | Serveur de distribution du binaire TuxBot | Haute |
| IP | `209.182.237[.]133` | Serveur de commande et contrôle (C2) de TuxBot v3 | Haute |
| Domaine | `digikalas[.]online` | URL secondaire de recherche de cible | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1110.001 | Initial Access | Brute Force: Password Guessing | Force brute automatisée sur les ports Telnet et SSH des dispositifs IoT cibles. |
| T1498 | Impact | Network Denial of Service | Déclenchement d'attaques DDoS volumétriques contre des infrastructures réseau cibles. |

---

### Sources

*   [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/)

---

<div id="google-gemini-cli-abuse-as-hacking-agent"></div>

## Détournement du CLI de Google Gemini en agent de piratage

---

### Résumé technique

Des cybercriminels ont développé une technique innovante détournant l'interface en ligne de commande officielle (CLI) de **Google Gemini** pour l'intégrer au sein d'architectures d'attaque. En exploitant des clés d'API Gemini légitimes, les attaquants utilisent les capacités d'interprétation logique du LLM directement depuis le shell système de la victime. 

L'outil permet d'abuser de la logique et de l'analyse du modèle de langage pour évaluer l'état local du système compromis, automatiser la prise de décision de post-exploitation et exécuter des instructions en boucle de type reverse shell guidées par l'intelligence artificielle. Ce comportement permet de contourner les détections comportementales classiques des EDR, les requêtes réseau malveillantes apparaissant comme du trafic d'API Google Cloud légitime.

---

### Analyse de l'impact

*   **Impact opérationnel** : Exécution de commandes offensives complexes automatisées par IA sur l'hôte, exfiltration d'informations assistée par prompt et persistance indétectable via l'API officielle Google.
*   **Sophistication** : Élevée. Utiliser les capacités d'agents autonomes d'un LLM légitime pour piloter un botnet représente une rupture technologique majeure dans les méthodes de C2.

---

### Recommandations

1.  Auditer et restreindre l'installation d'outils CLI et d'API d'IA génératives non requis sur les postes de travail de l'entreprise.
2.  Mettre en place des profils de sécurité interdisant aux clés d'API de l'entreprise d'exécuter des requêtes sans surveillance humaine directe ou contextes métiers approuvés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   S'assurer que la télémétrie réseau enregistre et catégorise l'ensemble des requêtes d'API dirigées vers les endpoints Google AI (`googleapis.com`).
*   Établir une base d'inventaire des clés d'API IA génératives valides au sein de l'organisation.

#### Phase 2 — Détection et analyse

*   Repérer les lancements suspects de requêtes répétitives et rapprochées vers le service Google Gemini CLI.
*   **Requête de Threat Hunting SIEM** :
    ```
    Image == "*gemini-cli*" OR CommandLine == "*gemini*"
    DestinationPort == 443 AND DestinationHost == "*googleapis.com*"
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Révoquer immédiatement la clé d'API Google Gemini compromise au niveau de la console Google Cloud Platform (GCP).
*   Isoler la machine hôte émettant des appels d'API suspects.

**Éradication :**
*   Supprimer l'outil de ligne de commande Gemini non autorisé du poste de travail.
*   Effacer les scripts d'orchestration qui appellent le CLI en arrière-plan.

**Récupération :**
*   Rétablir les configurations et auditer la machine compromise à la recherche d'autres modifications système effectuées par les scripts.

#### Phase 4 — Activités post-incident

*   Mettre en place un contrôle applicatif strict via l'EDR pour interdire le lancement d'outils d'IA génératives CLI non signés par l'entreprise.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Rechercher des flux de reverse-shell relayés via les adresses de l'API Google | T1059 | Logs de Proxy web / TLS | Identifier les serveurs internes émettant des flux continus persistants de longue durée vers des endpoints Google AI. |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `googleapis[.]com` | Endpoint légitime Google abusé pour le transit de commandes C2 | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1059 | Execution | Command and Scripting Interpreter | Utilisation de l'interpréteur de commandes du CLI Google Gemini pour exécuter des scripts offensifs locaux. |

---

### Sources

*   [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-gemini-cli-abused-as-a-hacking-agent-malware-botnet-operator/)

---

<div id="ai-vulnerability-vending-machine"></div>

## Développement d'une machine de vente de failles zero-day via IA

---

### Résumé technique

Des chercheurs en cybersécurité ont présenté une preuve de concept nommée "Vulnerability Vending Machine". Ce projet démontre la capacité de modèles d'IA de frontière (**FAIMs**) optimisés et configurés en réseau d'agents autonomes à rechercher de manière automatique, à découvrir et à exploiter de façon fonctionnelle des vulnérabilités complexes de type zero-day au sein de cibles d'applications web ou d'infrastructures cloud. 

Le système envoie des requêtes en continu, évalue les réponses du serveur et génère de façon dynamique des charges utiles (exploits) spécifiques et adaptées aux barrières de sécurité locales identifiées en un temps record de quelques minutes, à un coût d'exécution extrêmement bas de l'ordre de quelques dollars de jetons d'API (tokens).

---

### Analyse de l'impact

*   **Impact opérationnel** : Réduction radicale de la fenêtre de remédiation pour les équipes défensives. Les vulnérabilités logicielles découvrent un exploit fonctionnel quasi-immédiat, annulant les périodes de test de correctifs traditionnels.
*   **Sophistication** : Très élevée. Le chaînage intelligent d'agents spécialisés autonomes pour automatiser la conception de zero-day redéfinit le niveau de la menace cyber.

---

### Recommandations

1.  Adopter des approches de sécurité de type Zero Trust pour limiter l'impact d'une exploitation de périmètre réussie par l'IA.
2.  Accélérer et automatiser le processus de déploiement des correctifs critiques de sécurité pour réduire l'exposition temporelle.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Vérifier que les défenses de type pare-feu d'application web (WAF) intègrent des mécanismes d'analyse comportementale basés sur l'IA pour contrer les attaques de génération dynamique.
*   S'assurer de disposer d'architectures de redondance et de secours d'applications métiers critiques.

#### Phase 2 — Détection et analyse

*   Analyser les logs réseau pour identifier des campagnes de scan d'une rapidité et d'une adaptabilité inhabituelle (scans de vulnérabilités auto-correctifs).
*   **Requête de détection WAF** :
    ```
    RequestsCount > 1000 within 10 seconds
    IPAddress != TrustedIPs
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Isoler logiquement l'application ciblée par la campagne de scan en activant une page d'attente d'urgence.
*   Bloquer l'accès aux adresses IP à l'origine de l'exploitation automatisée au niveau du WAF.

**Éradication :**
*   Identifier la vulnérabilité exploitée et appliquer immédiatement le correctif ou de fausses réponses système pour tromper l'analyse de l'IA (honeypots).

**Récupération :**
*   Rétablir les services de l'application concernée après confirmation de la correction de la faille de sécurité.

#### Phase 4 — Activités post-incident

*   Mener une revue complète du code source de l'application à l'aide d'outils d'analyse statique et dynamique de nouvelle génération.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détecter des requêtes d'exploitation d'IA présentant des variations logiques rapides | T1595 | Logs d'accès HTTP | Analyser les logs d'accès à la recherche de modifications de paramètres rapides et de tentatives d'injection adaptatives provenant d'une même adresse IP source. |

---

### Indicateurs de compromission (DEFANG)

*   Aucun indicateur technique d'infrastructure répertorié pour cette preuve de concept générique.

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1595 | Reconnaissance | Active Scanning | Balayage et cartographie adaptative et autonome de la cible par un réseau d'agents d'IA de frontière. |

---

### Sources

*   [BleepingComputer](https://www.bleepingcomputer.com/news/security/we-built-a-vulnerability-vending-machine-ai-tokens-in-zero-days-out/)

---

<div id="gcp-serverless-hardening-exposed-cloud-functions"></div>

## Hardening des architectures serverless et des fonctions GCP exposées

---

### Résumé technique

Les analystes de Mandiant observent un ciblage intensif des architectures serverless et des services de micro-services mal sécurisés (tels que Google Cloud Run et les fonctions cloud GCP). L'essor de la vitesse de codage assisté par IA ("Vibe Coding") amène les développeurs à négliger les contrôles d'architecture logicielle essentiels. 

Les attaquants exploitent des vulnérabilités de type inclusion de fichiers locaux (LFI) au niveau d'endpoints de fonctions cloud exposées publiquement pour requérir et exfiltrer le jeton d'accès temporaire du compte de service géré par défaut (`Compute Engine default service account`) via l'accès au service de métadonnées interne (`metadata.google.internal`). Si ce compte par défaut possède des privilèges excessifs de type "Éditeur de projet", l'attaquant prend alors le contrôle total du projet GCP.

---

### Analyse de l'impact

*   **Impact opérationnel** : Compromission intégrale de l'environnement GCP de l'entreprise, exfiltration de données clients et déploiement d'instances de conteneurs frauduleuses à des fins de minage de crypto-monnaies ou d'infrastructures de rebond.
*   **Sophistication** : Moyenne. Repose sur l'oubli des règles de configuration de base des privilèges cloud et l'automatisation des scans d'endpoints.

---

### Recommandations

1.  Désactiver l'attribution automatique des privilèges d'éditeur de projet au compte de service par défaut GCP Compute Engine.
2.  Associer systématiquement chaque fonction cloud à un compte de service personnalisé appliquant le principe du moindre privilège.
3.  Activer la protection Web Application Firewall de Cloud Armor pour filtrer les tentatives de traversée de répertoires (LFI) sur les endpoints Cloud Run.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Mettre en place une surveillance de l'accès au service de métadonnées GCP (`169.254.169.254`) par les instances de fonctions cloud.
*   Vérifier que les extensions de sécurité GCP (IAM et audit logs) sont activées et centralisées.

#### Phase 2 — Détection et analyse

*   Analyser les logs d'activité pour repérer les requêtes d'exfiltration de secrets cloud d'une origine non autorisée.
*   **Requête de Threat Hunting GCP Admin Activity** :
    ```
    protoPayload.methodName="v1.compute.instances.insert"
    protoPayload.actorEmail="*compute@developer.gserviceaccount.com"
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Révoquer immédiatement les droits étendus du compte de service par défaut compromis.
*   Bloquer l'accès logique de la fonction cloud à l'origine de l'exfiltration au niveau des pare-feux VPC.

**Éradication :**
*   Supprimer ou isoler la fonction cloud vulnérable.
*   Vérifier l'absence d'instances d'intégration ou de machines virtuelles de minage nouvellement générées dans le projet.

**Récupération :**
*   Reconstruire la fonction cloud avec un compte de service dédié restreint et activer les contrôles de filtrage de requêtes Cloud Armor.

#### Phase 4 — Activités post-incident

*   Effectuer un audit d'architecture général des privilèges des rôles RBAC sur l'ensemble du tenant GCP de l'organisation.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détecter l'accès direct aux métadonnées GCP par des serveurs d'applications | T1580 | Logs réseaux GCP / VPC Flow Logs | Identifier les connexions réseau initiées vers l'adresse IP `169.254.169.254` provenant de services serverless non configurés pour interroger ces métadonnées. |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[:]//exampleabc01[.]com` | Serveur relais de test de rebond LFI cloud | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1580 | Discovery | Cloud Infrastructure Discovery | Analyse et extraction de la configuration IAM et de clés via des requêtes LFI dirigées vers les métadonnées GCP. |

---

### Sources

*   [Google Cloud Blog / Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/exposed-cloud-functions-harden/)

---

<div id="polinrider-malware-propagation"></div>

## Croissance de la surface d'attaque du malware PolinRider

---

### Résumé technique

Les rapports de télémétrie mettent en évidence une croissance explosive de la distribution de la souche malveillante open-source **PolinRider**, dont la surface d'attaque confirmée a été multipliée par 6,5 au cours des derniers mois. 

Ce programme malveillant multi-système est propagé activement par l'intermédiaire de fausses bibliothèques de développement logicielles et de dépôts communautaires corrompus. Une fois déployé localement, PolinRider procède à la modification furtive de fichiers système, collecte les cookies d'authentification des navigateurs et établit des liaisons de contrôle à distance persistantes avec des infrastructures de commande et de contrôle hébergées dans des réseaux d'hébergement anonymes.

---

### Analyse de l'impact

*   **Impact opérationnel** : Compromission de postes de travail de développeurs, vol massif de données confidentielles d'entreprises et persistance à long terme au sein du réseau local de l'organisation.
*   **Sophistication** : Moyenne. Repose sur l'exposition et la diffusion opportune de codes open-source corrompus pour infecter le parc informatique.

---

### Recommandations

1.  Déployer des contrôles d'intégrité locaux stricts interdisant aux utilisateurs de télécharger ou d'installer des paquets ou outils non révisés et approuvés par l'équipe de sécurité.
2.  Mettre à jour de manière continue les règles antivirus et de détection comportementale des agents d'endpoints.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   S'assurer que la base d'inventaire de signatures d'intrusions locales est configurée pour bloquer les variantes de charges identifiées de PolinRider.
*   Configurer l'EDR pour documenter les processus enfants lancés depuis des répertoires de téléchargement utilisateur.

#### Phase 2 — Détection et analyse

*   Analyser les logs de sécurité des machines pour repérer des comportements de modification de fichiers systèmes inhabituels associés au malware PolinRider.
*   **Requête de détection EDR** :
    ```
    ProcessName == "polinrider.exe" OR ImageCommandLine == "*polin*"
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Isoler du réseau de l'entreprise l'ordinateur de l'utilisateur sur lequel le malware a été repéré.
*   Suspendre temporairement l'accès de l'utilisateur concerné à l'Active Directory local.

**Éradication :**
*   Éliminer de façon définitive les exécutables du malware PolinRider et purger les caches des répertoires temporaires locaux.

**Récupération :**
*   Restaurer le poste affecté à partir d'une image système de confiance.

#### Phase 4 — Activités post-incident

*   Ajouter les variantes d'artefacts de PolinRider observées aux bases locales de signatures de blocage.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identifier des exécutions cachées de PolinRider | T1195 | Journaux système EDR | Rechercher des processus s'exécutant en arrière-plan d'une façon non autorisée depuis le dossier local d'installation de l'utilisateur. |

---

### Indicateurs de compromission (DEFANG)

*   Aucun indicateur spécifique répertorié dans les bulletins communautaires généraux pour cette souche en expansion.

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195 | Initial Access | Supply Chain Compromise | Utilisation d'extensions ou outils open-source trojanisés pour initier l'infection sur le poste de la victime. |

---

### Sources

*   [Open Source Malware Blog](https://opensourcemalware.com/blog/polinrider-blast-radius-grows)

---

<div id="office-365-phishing-campaigns"></div>

## Campagne d'hameçonnage Office 365 sur kuyhaa-me.pw

---

### Résumé technique

Une campagne d'hameçonnage active ciblant les utilisateurs de la suite Microsoft Office 365 a été détectée sur le domaine **kuyhaa-me[.]pw**. Les attaquants diffusent des liens de redirection via des e-mails frauduleux maquillés en notifications de partage de documents professionnels ou de réinitialisation de mots de passe de messagerie. 

L'utilisateur qui clique sur le lien est dirigé vers la page `hxxps[:]//kuyhaa-me[.]pw/dhtanx/Office/index[.]php`, qui affiche une réplique exacte et fonctionnelle de la mire d'authentification officielle de Microsoft Office 365. Les identifiants et mots de passe saisis au sein de cette fausse interface sont capturés et transmis en temps réel aux serveurs de l'attaquant.

---

### Analyse de l'impact

*   **Impact opérationnel** : Prise de contrôle de comptes de messagerie professionnels, compromission d'identités d'entreprise, exfiltration de communications internes confidentielles et risques de fraudes au président secondaires.
*   **Sophistication** : Faible à moyenne. Repose sur la réplication graphique de portails légitimes d'authentification Microsoft.

---

### Recommandations

1.  Déployer et imposer l'utilisation d'une authentification multifacteur (MFA) résistante à l'hameçonnage (FIDO2 / passkeys) pour l'ensemble des comptes de messagerie de l'organisation.
2.  Ajouter de façon immédiate le domaine `kuyhaa-me[.]pw` aux listes de blocage locales de vos pare-feux DNS et proxy web.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

*   Vérifier l'activation et la configuration de la solution antispam de messagerie pour intercepter les e-mails contenant des hyperliens vers des domaines nouvellement enregistrés ou suspects.
*   S'assurer que la fonction d'authentification double facteur MFA est obligatoire pour tout accès externe au tenant Office 365.

#### Phase 2 — Détection et analyse

*   Détecter les résolutions DNS ou connexions réseau sortantes d'utilisateurs de l'entreprise dirigées vers le domaine malveillant.
*   **Requête de détection Proxy / DNS** :
    ```
    DestinationHost == "kuyhaa-me.pw"
    ```

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
*   Révoquer instantanément la session d'authentification du compte de l'utilisateur s'étant connecté sur le domaine suspect.
*   Forcer une déconnexion générale de l'ensemble des terminaux liés au compte compromis.

**Éradication :**
*   Supprimer de façon urgente l'e-mail d'hameçonnage de toutes les boîtes de réception des collaborateurs via des scripts d'administration de messagerie.

**Récupération :**
*   Forcer la réinitialisation complète du mot de passe de l'utilisateur affecté et confirmer le bon enregistrement et le contrôle de son périphérique MFA légitime.

#### Phase 4 — Activités post-incident

*   Mettre à jour les politiques de filtrage antispam et sensibiliser le collaborateur touché à la vérification systématique de l'URL du portail d'authentification.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détecter l'accès à de faux portails Microsoft | T1566 | Logs de Proxy web / TLS | Identifier les requêtes web ciblant des chemins d'accès se terminant par `/Office/index.php` ou similaires hébergés en dehors des domaines officiels de Microsoft (`microsoftonline.com`). |

---

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[:]//kuyhaa-me[.]pw/dhtanx/Office/index[.]php` | Faux portail d'authentification Office 365 | Haute |
| Domaine | `kuyhaa-me[.]pw` | Domaine hébergeant la campagne d'hameçonnage | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566 | Initial Access | Phishing: Spearphishing Link | Envoi de messages frauduleux contenant des liens vers de fausses mires de connexion Office 365. |

---

### Sources

*   [URLDNA Exchange](https://infosec.exchange/@urldna/116926828272163279)

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