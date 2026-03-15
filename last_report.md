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
  * [AppsFlyer Web SDK compromis pour diffuser un malware de vol de crypto-monnaies](#appsflyer-web-sdk-compromis-pour-diffuser-un-malware-de-vol-de-crypto-monnaies)
  * [Interpol : L'Opération Synergia III démantèle 45 000 serveurs malveillants](#interpol--loperation-synergia-iii-demantele-45-000-serveurs-malveillants)
  * [La campagne SmartApeSG utilise des pages ClickFix pour diffuser le RAT Remcos](#la-campagne-smartapesg-utilise-des-pages-clickfix-pour-diffuser-le-rat-remcos)
  * [Storm-2561 usurpe des sites VPN pour dérober des identifiants d'entreprise](#storm-2561-usurpe-des-sites-vpn-pour-derober-des-identifiants-dentreprise)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber actuel est marqué par une intensification des attaques sur la chaîne d'approvisionnement, illustrée par la compromission du SDK d'AppsFlyer impactant des milliers d'applications web. Parallèlement, des groupes comme Storm-2561 et SmartApeSG affinent leurs méthodes d'accès initial en utilisant le "SEO poisoning" et des techniques d'ingénierie sociale sophistiquées comme "ClickFix" (faux CAPTCHA). L'exploitation active de vulnérabilités Zero-day dans les navigateurs, notamment Chrome, demeure un vecteur critique nécessitant une réactivité immédiate des équipes de sécurité. On observe également une menace croissante sur les infrastructures d'IA, avec des vulnérabilités permettant le vol de propriété intellectuelle. Toutefois, la coopération internationale porte ses fruits, comme le montre l'opération Synergia III d'Interpol qui a neutralisé des dizaines de milliers d'infrastructures malveillantes. Les entreprises doivent renforcer la surveillance de leurs bibliothèques tierces et sécuriser prioritairement les accès distants (VPN). La gestion des correctifs sans interruption (hotpatching) devient une nécessité stratégique pour les services critiques. Enfin, la sensibilisation des employés reste primordiale face à des campagnes de phishing toujours plus ciblées sur les portails internes.

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
| SmartApeSG | Multi-secteurs | Infiltration de sites légitimes, faux CAPTCHA (ClickFix), diffusion du RAT Remcos | [SANS ISC](https://isc.sans.edu/diary/rss/32796) |
| Storm-2561 | Entreprises (utilisateurs de VPN) | SEO Poisoning, usurpation de sites de téléchargement VPN (Cisco, Fortinet, Ivanti), Infostealer Hyrax | [Security Affairs](https://securityaffairs.com/189426/cyber-crime/storm-2561-lures-victims-to-spoofed-vpn-sites-to-harvest-corporate-logins.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| International (72 pays) | Coopération policière | L'opération Synergia III, coordonnée par INTERPOL, a permis le démantèlement de 45 000 infrastructures malveillantes et 94 arrestations. | [Security Affairs](https://securityaffairs.com/189420/cyber-crime/interpol-operation-synergia-iii-leads-to-45000-malicious-ips-dismantled-and-94-arrests-worldwide.html) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Néant | - | - | - | - | Aucune nouvelle réglementation mentionnée dans les articles analysés. | - |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Restauration | Starbucks | Accès non autorisé à 889 comptes d'employés via un portail "Partner Central" usurpé (phishing). Vol de SSN et coordonnées bancaires. | [Security Affairs](https://securityaffairs.com/189438/security/starbucks-data-breach-impacts-889-employees.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-25750 | 9.8 (Critique) | LangSmith (AI Monitoring) | Prise de contrôle de compte (Insecure API configuration) | [Cybersecurity News](https://cybersecuritynews.com/critical-langsmith-account-takeover-vulnerability/) |
| CVE-2026-3909 | 8.8 (Élevé) | Google Chrome (Skia) | Out-of-bounds Write (Zero-day exploitée) | [The Cyber Throne](https://thecyberthrone.in/2026/03/14/cisa-adds-two-google-chrome-zero-days-to-kev/) / [Security.nl](https://www.security.nl/posting/928543/Google+meldde+ten+onrechte+dat+Chrome-lek+was+gedicht%2C+rolt+nieuwe+update+uit?channel=rss) |
| CVE-2026-3910 | 8.8 (Élevé) | Google Chrome (V8) | Inappropriate Implementation (Zero-day exploitée) | [The Cyber Throne](https://thecyberthrone.in/2026/03/14/cisa-adds-two-google-chrome-zero-days-to-kev/) / [Security.nl](https://www.security.nl/posting/928543/Google+meldde+ten+onrechte+dat+Chrome-lek+was+gedicht%2C+rolt+nieuwe+update+uit?channel=rss) |
| CVE-2026-25172 | Élevé | Windows 11 RRAS | Exécution de code à distance (RCE) | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-11-oob-hotpatch-to-fix-rras-rce-flaw/) |
| CVE-2026-25173 | Élevé | Windows 11 RRAS | Exécution de code à distance (RCE) | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-11-oob-hotpatch-to-fix-rras-rce-flaw/) |
| CVE-2026-26111 | Élevé | Windows 11 RRAS | Exécution de code à distance (RCE) | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-11-oob-hotpatch-to-fix-rras-rce-flaw/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| AppsFlyer Web SDK hijacked to spread crypto-stealing JavaScript code | Menace critique sur la supply chain impactant des milliers d'applications. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/appsflyer-web-sdk-used-to-spread-crypto-stealer-javascript-code/) |
| Interpol – Operation Synergia III leads to 45,000 malicious IPs dismantled | Actualité majeure sur le démantèlement d'infrastructures cybercriminelles mondiales. | [Security Affairs](https://securityaffairs.com/189420/cyber-crime/interpol-operation-synergia-iii-leads-to-45000-malicious-ips-dismantled-and-94-arrests-worldwide.html) |
| SmartApeSG campaign uses ClickFix page to push Remcos RAT | Analyse technique d'une campagne active utilisant des techniques d'ingénierie sociale modernes. | [SANS ISC](https://isc.sans.edu/diary/rss/32796) |
| Storm-2561 lures victims to spoofed VPN sites to harvest corporate logins | Risque élevé pour les accès distants en entreprise via SEO poisoning. | [Security Affairs](https://securityaffairs.com/189426/cyber-crime/storm-2561-lures-victims-to-spoofed-vpn-sites-to-harvest-corporate-logins.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| CISA Adds Two Google Chrome Zero-Days to KEV | Contenu exclusivement axé sur des vulnérabilités déjà traitées en synthèse. | [The Cyber Throne](https://thecyberthrone.in/2026/03/14/cisa-adds-two-google-chrome-zero-days-to-kev/) |
| Critical LangSmith Account Takeover Vulnerability Puts Users at Risk | Publication focalisée sur une vulnérabilité spécifique traitée en synthèse. | [Cybersecurity News](https://cybersecuritynews.com/critical-langsmith-account-takeover-vulnerability/) |
| Google meldde ten onrechte dat Chrome-lek was gedicht, rolt nieuwe update uit | Doublon thématique sur les vulnérabilités Chrome déjà traitées. | [Security.nl](https://www.security.nl/posting/928543/Google+meldde+ten+onrechte+dat+Chrome-lek+was+gedicht%2C+rolt+nieuwe+update+uit?channel=rss) |
| Microsoft releases Windows 11 OOB hotpatch to fix RRAS RCE flaw | Publication focalisée sur des vulnérabilités spécifiques traitées en synthèse. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-11-oob-hotpatch-to-fix-rras-rce-flaw/) |
| Starbucks data breach impacts 889 employees | Article sur une violation de données, exclu des synthèses d'articles selon les critères. | [Security Affairs](https://securityaffairs.com/189438/security/starbucks-data-breach-impacts-889-employees.html) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="appsflyer-web-sdk-compromis-pour-diffuser-un-malware-de-vol-de-crypto-monnaies"></div>

## AppsFlyer Web SDK hijacked to spread crypto-stealing JavaScript code
Le SDK Web d'AppsFlyer, utilisé par plus de 15 000 entreprises, a subi une attaque de type supply chain via une compromission de leur registraire de domaine. Entre le 9 et le 11 mars 2026, du code JavaScript malveillant a été injecté dans le fichier servi par `websdk.appsflyer.com`. Ce script interceptait les adresses de portefeuilles de crypto-monnaies (Bitcoin, Ethereum, Solana, etc.) saisies par les utilisateurs sur les sites clients pour les remplacer par celles de l'attaquant. Bien que le SDK mobile ne soit pas affecté, des milliers d'applications web ont potentiellement diffusé ce payload. L'attaquant a utilisé l'obfuscation pour masquer son activité tout en maintenant les fonctions légitimes du SDK. AppsFlyer a confirmé l'incident et affirme avoir repris le contrôle du domaine. Cette attaque souligne la fragilité des dépendances tierces massivement déployées.

**Analyse de l'impact** : L'impact est potentiellement massif en raison de l'omniprésence du SDK d'AppsFlyer. Le vol financier direct des utilisateurs finaux peut nuire gravement à la réputation des entreprises clientes et entraîner des pertes financières directes.

**Recommandations** :
* Examiner les journaux de télémétrie réseau pour détecter des requêtes API suspectes provenant de `websdk.appsflyer.com` sur la période du 9 au 11 mars.
* Effectuer une rétrogradation (downgrade) vers une version connue et saine du SDK ou s'assurer de charger la version corrigée post-11 mars.
* Mettre en œuvre des politiques de Content Security Policy (CSP) restrictives pour limiter l'exécution de scripts tiers non vérifiés.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (ShinyHunters cité pour contexte passé) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise: SW Dependencies<br/>* T1566: Phishing (Redirect)<br/>* T1059.007: JavaScript execution |
| Observables & Indicateurs de compromission | ```* websdk.appsflyer.com``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/appsflyer-web-sdk-used-to-spread-crypto-stealer-javascript-code/

<br/>
<br/>

<div id="interpol--loperation-synergia-iii-demantele-45-000-serveurs-malveillants"></div>

## Interpol – Operation Synergia III leads to 45,000 malicious IPs dismantled and 94 arrests worldwide
L'opération Synergia III, menée par INTERPOL entre juillet 2025 et janvier 2026, a porté un coup majeur à la cybercriminalité mondiale. Impliquant 72 pays, cette action a permis de neutraliser 45 000 adresses IP malveillantes et serveurs liés au phishing, aux ransomwares et aux malwares. Au total, 94 individus ont été arrêtés et 110 autres font l'objet d'enquêtes approfondies. Les forces de l'ordre ont saisi 212 appareils électroniques lors de raids coordonnés. À Macao, plus de 33 000 sites de phishing imitant des banques et des casinos ont été identifiés. Au Bangladesh et au Togo, des réseaux de fraude aux prêts et d'extorsion ont été démantelés. L'opération a bénéficié du soutien technique de sociétés privées comme Group-IB, Trend Micro et S2W.

**Analyse de l'impact** : Cette opération réduit significativement la capacité opérationnelle de nombreux réseaux cybercriminels à court terme. Elle renforce la dissuasion globale et démontre l'efficacité des partenariats public-privé dans la lutte contre les infrastructures malveillantes.

**Recommandations** :
* Les équipes de Threat Hunting doivent corréler leurs logs avec les listes d'IP démantelées par Interpol si celles-ci sont publiées via les flux de renseignement partenaires (Group-IB, Trend Micro).
* Maintenir une veille sur les nouvelles infrastructures de remplacement qui seront inévitablement créées par les acteurs non appréhendés.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Réseaux de phishing et de fraude non nommés individuellement |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1583.003: Acquire Infrastructure: Virtual Private Server<br/>* T1566: Phishing |
| Observables & Indicateurs de compromission | ```45 000 adresses IP malveillantes neutralisées (détails via flux partenaires INTERPOL)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189420/cyber-crime/interpol-operation-synergia-iii-leads-to-45000-malicious-ips-dismantled-and-94-arrests-worldwide.html

<br/>
<br/>

<div id="la-campagne-smartapesg-utilise-des-pages-clickfix-pour-diffuser-le-rat-remcos"></div>

## SmartApeSG campaign uses ClickFix page to push Remcos RAT
La campagne SmartApeSG (également connue sous les noms ZPHP ou HANEYMANEY) utilise désormais des techniques "ClickFix" pour infecter les utilisateurs. L'attaque commence par l'injection d'un script malveillant dans des sites web légitimes compromis. Ce script génère un faux CAPTCHA invitant l'utilisateur à prouver qu'il est humain. Une fois la case cochée, des instructions s'affichent, demandant à l'utilisateur de copier une commande PowerShell dans le presse-papiers, d'ouvrir une fenêtre "Exécuter" et de la coller. Cette action télécharge et exécute une archive ZIP déguisée en fichier PDF. Le contenu déploie le cheval de Troie d'accès à distance (RAT) Remcos via une technique de DLL side-loading. L'infection est rendue persistante via une modification de la base de registre Windows.

**Analyse de l'impact** : Le RAT Remcos permet un contrôle total de la machine infectée, incluant l'exfiltration de données, l'enregistrement de frappe et l'accès à la webcam. L'ingénierie sociale via ClickFix est particulièrement efficace car elle contourne les solutions de filtrage d'URL classiques.

**Recommandations** :
* Bloquer les domaines d'infrastructure identifiés (ex: `retrypoti[.]top`, `forcebiturg[.]com`).
* Sensibiliser les utilisateurs à ne jamais copier/coller des commandes inconnues dans la fenêtre "Exécuter" (Run).
* Surveiller les exécutions PowerShell suspectes avec des arguments encodés ou des connexions réseau vers des IP inhabituelles.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | SmartApeSG |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.002: User Execution: Malicious File<br/>* T1574.002: Hijack Execution Flow: DLL Side-Loading<br/>* T1059.001: PowerShell execution |
| Observables & Indicateurs de compromission | ```* hxxps://cpajoliette[.]com/d.js
* hxxps://retrypoti[.]top/endpoint/signin-cache.js
* hxxp://forcebiturg[.]com/boot
* 193.178.170.155 (TLS Remcos)
* b170ffc8612618c822eb03030a8a62d4be8d6a77a11e4e41bb075393ca504ab7 (ZIP/Malware)``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32796

<br/>
<br/>

<div id="storm-2561-usurpe-des-sites-vpn-pour-derober-des-identifiants-dentreprise"></div>

## Storm-2561 lures victims to spoofed VPN sites to harvest corporate logins
Le groupe Storm-2561 mène une vaste campagne de vol d'identifiants en utilisant le "SEO poisoning" pour manipuler les résultats de recherche. Les attaquants créent des sites web imitant les portails de téléchargement de VPN reconnus tels que Cisco AnyConnect, Fortinet et Ivanti Pulse Secure. Les victimes, cherchant à télécharger ces clients, sont redirigées vers des archives ZIP malveillantes hébergées sur GitHub. L'installeur MSI trojanisé utilise le DLL side-loading pour déployer l'infostealer "Hyrax". Ce dernier dérobe non seulement les identifiants saisis, mais aussi les fichiers de configuration de connexion VPN stockés localement. Pour tromper l'utilisateur, l'installeur affiche un faux message d'erreur après le vol et redirige vers le site officiel pour une installation légitime, masquant ainsi toute trace d'infection.

**Analyse de l'impact** : Cette menace est critique pour la sécurité périmétrique des entreprises. Le vol de configurations et d'identifiants VPN permet aux attaquants de pénétrer directement dans le réseau interne, facilitant des attaques ultérieures comme le déploiement de ransomwares.

**Recommandations** :
* Restreindre la capacité des utilisateurs à installer des logiciels non approuvés (privilèges administrateur).
* Surveiller les modifications de la clé de registre `RunOnce` et l'exécution du processus `Pulse.exe` depuis des répertoires non standards.
* Imposer l'authentification multi-facteurs (MFA) pour tous les accès VPN afin de mitiger le vol d'identifiants.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Storm-2561 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1588.004: Search Engine Optimization (SEO) Poisoning<br/>* T1036: Masquerading<br/>* T1547.001: Boot or Logon Autostart Execution: Registry Run Keys |
| Observables & Indicateurs de compromission | ```* 194.76.226.93:8080 (C2)
* Pulse.exe (malveillant)
* C:\ProgramData\Pulse Secure\ConnectionStore\connectionstore.dat (Cible)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189426/cyber-crime/storm-2561-lures-victims-to-spoofed-vpn-sites-to-harvest-corporate-logins.html