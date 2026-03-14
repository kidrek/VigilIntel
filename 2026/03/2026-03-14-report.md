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
  * [attaque destructrice et espionnage lié au conflit irano-israélien](#attaque-destructrice-et-espionnage-lie-au-conflit-irano-israelien)
  * [operation synergia iii et demantelement de socksescort](#operation-synergia-iii-et-demantelement-de-socksescort)
  * [zero-days chrome activement exploites cve-2026-3909 et cve-2026-3910](#zero-days-chrome-activement-exploites-cve-2026-3909-et-cve-2026-3910)
  * [campagne storm-2561 ciblant les vpn d’entreprise](#campagne-storm-2561-ciblant-les-vpn-dentreprise)
  * [ivanti epmm : persistance via sleeper shells](#ivanti-epmm-persistance-via-sleeper-shells)
  * [hive0163 et lusage de malwares generes par ia slopoly](#hive0163-et-lusage-de-malwares-generes-par-ia-slopoly)
  * [espionnage russe sur les messageries chiffrees signal et whatsapp](#espionnage-russe-sur-les-messageries-chiffrees-signal-et-whatsapp)
  * [vulnerabilite critique sql injection dans le plugin wordpress ally](#vulnerabilite-critique-sql-injection-dans-le-plugin-wordpress-ally)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace est dominé par une hybridation croissante entre cyber-opérations militaires et cybercriminalité organisée. L'escalade du conflit entre l'Iran, Israël et les États-Unis a déclenché des attaques destructrices majeures, notamment le sabotage de l'infrastructure mondiale de Stryker via l'abus de solutions MDM, marquant un tournant dans l'utilisation de capacités étatiques contre des cibles commerciales. Parallèlement, l'année 2026 s'ouvre sur une pression extrême sur les navigateurs web, avec la découverte et l'exploitation immédiate de plusieurs failles Zero-day dans Google Chrome. Les forces de l'ordre marquent des points significatifs via les opérations Synergia III et Lightning, démantelant des réseaux de botnets massifs comme AVrecon et SocksEscort. On observe également une démocratisation de l'IA générative par des groupes comme Hive0163 pour produire des malwares polymorphes, compliquant la détection traditionnelle. L'espionnage ciblant les communications chiffrées (Signal/WhatsApp) par des acteurs russes confirme que la confidentialité des échanges reste une cible prioritaire pour le renseignement étatique. Enfin, le détournement des outils d'administration (Intune, VPN, RMM) s'impose comme le vecteur d'accès privilégié pour les attaques à fort impact.
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
| **313 Team** | Gouvernements (Roumanie, Koweït) | Attaques DDoS massives pour raisons politiques | Flare.io |
| **APT28 (Pawn Storm)** | Diplomatie, Gouvernements, Journalistes | Phishing, exploitation de Zero-days MSHTML | Flare.io |
| **Handala Hack** | Santé, Énergie, Finance | Wiper (effacement de données) via abus de MDM Intune, exfiltration massive | Flare.io, SentinelOne |
| **Hive0163** | Multitâche (financièrement motivé) | Usage de malwares générés par IA (Slopoly), Ransomware | Security Affairs |
| **Keymous Plus** | Gouvernements du Golfe | Campagnes DDoS rotatives à grande échelle | Flare.io |
| **SmartApeSG** | Tout secteur | Injection de scripts ClickFix, faux CAPTCHA pour distribuer Remcos RAT | ISC SANS |
| **Storm-2561** | Tout secteur (Utilisateurs VPN) | SEO Poisoning, faux installateurs de clients VPN (Ivanti, Cisco) | BleepingComputer |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Infrastructure Nucléaire | Pologne | Tentative d'attaque cyber contre le Centre National de Recherche Nucléaire (NCBJ). | Security Affairs, BleepingComputer |
| Défense / Diplomatie | UK / Afghanistan | Fuite de données du Ministère de la Défense britannique concernant 18 700 Afghans. | DataBreaches.net |
| Énergie / Transport | Iran / Golfe | Blocus numérique en Iran (connectivité à 1%) et cyberattaques sur le transport maritime pétrolier. | Recorded Future, IRIS |
| Relations Internationales | Russie / Ukraine | Campagnes de désinformation russes liant le conflit en Iran à la crise ukrainienne. | EUvsDisinfo |
| Sport / Diplomatie | Monde / USA | Tensions diplomatiques sur la participation de l'Iran à la Coupe du Monde 2026. | IRIS |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| BOD 22-01 Update | CISA | 13/03/2026 | USA | Binding Operational Directive 22-01 | Obligation pour les agences fédérales de corriger les failles Chrome exploitées. | Security Affairs |
| ENISA Technical Advisory | ENISA | 12/03/2026 | UE | DevSecOps Guidance | Recommandations sur la sécurisation des gestionnaires de paquets logiciels. | Security Affairs |
| SEC 8-K Filings | Stryker | 12/03/2026 | USA | SEC Reporting | Notification officielle d'un incident cyber majeur ayant un impact financier. | Flare.io |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Énergie | Sharjah National Oil Corp | Exfiltration de 1,3 To de données (contrats, dossiers financiers). | Flare.io |
| Gouvernement | MoD (Royaume-Uni) | Fuite d'informations sensibles sur 18 700 ressortissants afghans. | DataBreaches.net |
| Santé | Stryker Corporation | Exfiltration de 50 To de données suivie d'un effacement (wiper) des systèmes. | Flare.io, SentinelOne |
| Santé | Bell Ambulance | Violation de données impactant plus de 238 000 personnes. | Security Affairs |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2025-15060 | 9.8 | Claude-hovercraft | Exécution de code à distance (RCE) | CVE Feed |
| CVE-2026-32626 | 9.7 | AnythingLLM Desktop | XSS vers RCE | Mastodon / OffSeq |
| CVE-2026-3083 | 8.8 | GStreamer | Out-of-bounds Write / RCE | CVE Feed |
| CVE-2026-3909 | 8.8 | Google Chrome (Skia) | Heap Corruption (Exploitée) | CERT-FR, CISA |
| CVE-2026-3910 | 8.8 | Google Chrome (V8) | Arbitrary Code Execution (Exploitée) | CERT-FR, CISA, SOC Prime |
| CVE-2026-32627 | 8.7 | cpp-httplib | Bypass de vérification TLS | CVE Feed |
| CVE-2026-3227 | 8.5 | TP-Link (WR802N/841N/840N) | Command Injection | CVE Feed |
| CVE-2026-32729 | 8.1 | Runtipi | Bypass de 2FA (Brute-force) | CVE Feed |
| CVE-2026-2413 | - | WordPress (Ally plugin) | SQL Injection critique | HackRead |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Monitoring Cyberattacks Linked to US-Israel-Iran Conflict | Analyse détaillée d'une cyber-guerre étatique majeure en cours. | https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict |
| Police sinkholes 45,000 IP addresses | Succès majeur de coopération internationale contre l'infrastructure cybercriminelle. | https://www.bleepingcomputer.com/news/security/police-sinkholes-45-000-ip-addresses-in-cybercrime-crackdown/ |
| Multiples vulnérabilités dans Google Chrome | Alerte critique sur des Zero-days activement exploités. | https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0286/ |
| Fake enterprise VPN sites used to steal company credentials | Tactique de phishing sophistiquée ciblant l'accès initial en entreprise. | https://www.bleepingcomputer.com/news/security/fake-enterprise-vpn-downloads-used-to-steal-company-credentials/ |
| Ivanti EPMM ‘Sleeper Shells’ not so sleepy? | Analyse technique sur la persistance post-exploitation. | https://blog.nviso.eu/2026/03/13/ivanti-epmm-sleeper-shells-not-so-sleepy/ |
| AI-assisted Slopoly malware powers Hive0163 | Illustration concrète de l'usage de l'IA par les attaquants. | https://securityaffairs.com/189378/malware/ai-assisted-slopoly-malware-powers-hive0163s-ransomware-campaigns.html |
| Signal support : une vraie campagne d'espionnage russe | Ciblage d'outils de communication sécurisés pour des cibles de haut niveau. | https://www.lemonde.fr/pixels/article/2026/03/13/signal-support-un-faux-message-d-alerte-une-vraie-campagne-d-espionnage-des-utilisateurs-de-la-messagerie-attribuee-a-la-russie_6671046_4408996.html |
| SQL Injection in Ally WordPress Plugin Exposes 200K+ Sites | Risque massif sur la chaîne d'approvisionnement web. | https://hackread.com/sql-injection-vulnerability-ally-wordpress-plugin/ |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Friday, March 13th | Podcast sans contenu textuel exploitable directement. | https://isc.sans.edu/diary/rss/32792 |
| From VMware to what’s next | Contenu sponsorisé par un éditeur (Acronis). | https://www.bleepingcomputer.com/news/security/from-vmware-to-whats-next-protecting-data-during-hypervisor-migration/ |
| Meet the CE SentinelOne Assistant | Annonce d'un outil personnel/communautaire. | https://www.cyberengage.org/post/meet-the-ce-sentinelone-assistant-i-built-it-for-myself-but-you-can-try-it-too |
| Beyond File Servers | Article d'opinion sur l'architecture de données. | https://securityaffairs.com/189368/security/beyond-file-servers-securing-unstructured-data-in-the-era-of-ai.html |
| Who Will Pay the Cost of Freedom in Europe? | Analyse économique et politique, pas purement cyber. | https://www.rusi.org/explore-our-research/publications/commentary/who-will-pay-cost-freedom-europe |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="attaque-destructrice-et-espionnage-lie-au-conflit-irano-israelien"></div>

## Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict
Le conflit entre les États-Unis, Israël et l'Iran a atteint un niveau de cyberguerre sans précédent, structuré en trois phases depuis juin 2025. L'incident le plus marquant concerne la société Stryker, victime d'une attaque par wiper revendiquée par le groupe Handala (lié au MOIS iranien). Les attaquants ont utilisé l'accès à la console Microsoft Intune pour déclencher des commandes de "remote wipe" (effacement à distance) sur plus de 200 000 appareils dans 79 pays. Parallèlement, des campagnes DDoS massives ciblent les ministères de plusieurs pays arabes accusés de soutenir les États-Unis. Des tentatives d'intrusion contre le centre nucléaire polonais NCBJ ont également été détectées. L'Iran impose un blackout quasi-total sur son internet national pour limiter les cyber-répliques occidentales. La menace s'étend désormais aux entreprises technologiques américaines comme Google, Microsoft et Nvidia, explicitement désignées comme cibles par les autorités iraniennes.

**Analyse de l'impact** : Impact critique sur la continuité des activités mondiales dans le secteur de la santé (Stryker) et menace directe sur les infrastructures critiques de l'OTAN (Pologne, Roumanie).

**Recommandations** : 
*   Sécuriser les accès aux consoles MDM (Intune, AirWatch) avec une authentification multifacteur (MFA) robuste et des restrictions IP.
*   Auditer les privilèges d'administration "Remote Wipe" et mettre en place des alertes sur l'utilisation massive de cette fonctionnalité.
*   Renforcer la surveillance des actifs exposés pour les entreprises ayant des liens commerciaux avec Israël ou des opérations au Moyen-Orient.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack (Void Manticore), MuddyWater, 313 Team, CyberAv3ngers |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1078: Valid Accounts (Abus de comptes MDM) <br/> • T1485: Data Destruction (Wiper) <br/> • T1498: Network Denial of Service |
| Observables & Indicateurs de compromission | ```• handala-hack.io • Intune console unauthorized access • Patterns de wipers sur endpoints Windows/Linux``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://www.recordedfuture.com/blog/the-iran-war-what-you-need-to-know
* https://www.sentinelone.com/blog/the-good-the-bad-and-the-ugly-in-cybersecurity-week-11-7/

<br>
<br>

<div id="operation-synergia-iii-et-demantelement-de-socksescort"></div>

## Police sinkholes 45,000 IP addresses in cybercrime crackdown
L'opération internationale "Synergia III", menée par Interpol, a permis de neutraliser plus de 45 000 adresses IP malveillantes et de saisir des serveurs liés à des activités de phishing, malwares et ransomwares. En parallèle, l'opération "Lightning" a démantelé SocksEscort, un service de proxy malveillant alimenté par le botnet AVrecon. Ce réseau utilisait environ 360 000 routeurs résidentiels infectés pour permettre aux cybercriminels de masquer leur origine lors de fraudes bancaires et d'attaques DDoS. Les autorités de 72 pays ont participé à ces actions, aboutissant à 94 arrestations. Les pertes financières évitées se chiffrent en millions de dollars, incluant des vols de cryptomonnaies. L'enquête a révélé que les appareils étaient souvent infectés via des vulnérabilités connues non corrigées dans les modems SOHO.

**Analyse de l'impact** : Réduction significative de l'infrastructure de dissimulation disponible pour les attaquants, perturbant les campagnes de phishing et de fraude à grande échelle.

**Recommandations** : 
*   Mettre à jour systématiquement le firmware des routeurs résidentiels et modems (SOHO).
*   Utiliser des flux de threat intelligence intégrant les IP récemment sinkholées par Interpol pour nettoyer les accès internes.
*   Surveiller les flux sortants inhabituels vers des noeuds de botnet connus.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Réseaux de botnet AVrecon et opérateurs de SocksEscort |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1584: Compromise Infrastructure <br/> • T1090: Proxy |
| Observables & Indicateurs de compromission | ```• Botnet AVrecon binaries • 45,000 sinkholed IPs (via Interpol feeds)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/police-sinkholes-45-000-ip-addresses-in-cybercrime-crackdown/
* https://securityaffairs.com/189391/security/us-and-european-authorities-disrupt-socksescort-proxy-service-tied-to-avrecon-botnet.html
* https://databreaches.net/2026/03/13/45000-malicious-ip-addresses-taken-down-in-international-cyber-operation/

<br>
<br>

<div id="zero-days-chrome-activement-exploites-cve-2026-3909-et-cve-2026-3910"></div>

## Multiples vulnérabilités dans Google Chrome (CVE-2026-3909 et CVE-2026-3910)
Google a publié une mise à jour d'urgence pour corriger deux vulnérabilités de haute sévérité activement exploitées dans le monde réel. La faille CVE-2026-3909 concerne une écriture hors limites dans la bibliothèque graphique Skia, pouvant entraîner une corruption de mémoire. La seconde, CVE-2026-3910, réside dans le moteur JavaScript V8 et permet l'exécution de code arbitraire à l'intérieur de la sandbox du navigateur. Ces failles sont déclenchables via la simple consultation d'une page HTML malveillante. La CISA a ajouté ces vulnérabilités à son catalogue KEV, imposant une correction aux agences fédérales avant le 27 mars 2026. L'absence de détails techniques publics suggère que l'exploitation est encore limitée à des acteurs sophistiqués.

**Analyse de l'impact** : Risque majeur de compromission de postes de travail via une simple navigation web ("drive-by download").

**Recommandations** : 
*   Déployer immédiatement la version 146.0.7680.75/76 (ou supérieure) de Google Chrome sur tous les systèmes.
*   Forcer le redémarrage des navigateurs pour valider l'installation du correctif.
*   Surveiller les versions de navigateurs tiers basés sur Chromium (Edge, Brave) pour leurs mises à jour respectives.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (exploitation active confirmée) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1203: Exploitation for Client Execution <br/> • T1189: Drive-by Compromise |
| Observables & Indicateurs de compromission | ```• Versions antérieures à 146.0.7680.75 • Requêtes vers domaines suspects suite à navigation web``` |

### Source (url) du ou des articles
* https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0286/
* https://securityaffairs.com/189373/hacking/google-fixed-two-new-actively-exploited-flaws-in-the-chrome-browser.html
* https://socprime.com/blog/cve-2026-3910-vulnerability/

<br>
<br>

<div id="campagne-storm-2561-ciblant-les-vpn-dentreprise"></div>

## Fake enterprise VPN sites used to steal company credentials
L'acteur de menace Storm-2561 utilise des techniques de "SEO poisoning" pour diriger les utilisateurs vers de faux sites de téléchargement de VPN d'entreprise (Ivanti, Cisco, Fortinet). Les victimes téléchargent un fichier ZIP contenant un installateur MSI malveillant. Une fois exécuté, le logiciel installe un véritable client VPN mais injecte simultanément le malware "Hyrax infostealer". Le malware présente une interface de connexion identique à l'originale pour capturer les identifiants. Pour éviter la détection, il affiche une erreur d'installation après le vol des données et redirige l'utilisateur vers le site officiel. Le malware établit une persistance via la clé de registre Windows `RunOnce`.

**Analyse de l'impact** : Risque critique de vol d'accès initiaux à haut privilège permettant des intrusions ultérieures de type ransomware ou espionnage.

**Recommandations** : 
*   Éduquer les utilisateurs sur le téléchargement de logiciels uniquement via le portail applicatif interne ou les sources officielles.
*   Bloquer l'exécution de binaires non signés ou signés par des certificats révoqués (ex: Taiyuan Lihua Near IT Co.).
*   Surveiller la création de fichiers dans `%CommonFiles%\Pulse Secure` et les modifications de la clé `RunOnce`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Storm-2561 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1566.002: Spearphishing Link (SEO poisoning) <br/> • T1036: Masquerading <br/> • T1539: Steal Web Session Cookie |
| Observables & Indicateurs de compromission | ```• Pulse.exe (malveillant) • dwmapi.dll (loader) • inspector.dll (Hyrax) • connectionsstore.dat (volé)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/fake-enterprise-vpn-downloads-used-to-steal-company-credentials/

<br>
<br>

<div id="ivanti-epmm-persistance-via-sleeper-shells"></div>

## Ivanti EPMM ‘Sleeper Shells’ not so sleepy?
Des recherches récentes sur les vulnérabilités CVE-2026-1281 et CVE-2026-1340 affectant Ivanti EPMM (anciennement MobileIron Core) révèlent une campagne active utilisant des "Sleeper Shells". Un fichier `403.jsp` est injecté pour servir de chargeur de classe Java furtif. Contrairement aux premiers rapports suggérant un outil dormant, NVISO a observé des commandes actives visant à exfiltrer des bases de données LDAP et des configurations système (`tar` de `/mi/tomcat-properties`). Les attaquants utilisent des requêtes HTTP avec des paramètres encodés en Base64 pour exécuter des scripts de reconnaissance et de nettoyage automatisés. Cette technique permet de maintenir un accès persistant même après l'application des correctifs si le système a déjà été compromis.

**Analyse de l'impact** : Compromission totale des données de gestion des terminaux mobiles (MDM), incluant les identifiants LDAP des utilisateurs.

**Recommandations** : 
*   Vérifier la présence du fichier `/mifs/403.jsp` sur les instances Ivanti EPMM.
*   Analyser les logs Tomcat pour des requêtes vers des fichiers JSP inhabituels avec des paramètres courts (ex: `?k=`).
*   En cas de détection, procéder à une réinitialisation complète de l'instance et des secrets LDAP associés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Inconnu (lié à la campagne 403.jsp) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1505.003: Web Shell <br/> • T1059.004: OS Command Shell |
| Observables & Indicateurs de compromission | ```• /mifs/403.jsp • /mi/tomcat/webapps/mifs/css/mibasecss.css • Paramètre k0f53cf964d387``` |

### Source (url) du ou des articles
* https://blog.nviso.eu/2026/03/13/ivanti-epmm-sleeper-shells-not-so-sleepy/

<br>
<br>

<div id="hive0163-et-lusage-de-malwares-generes-par-ia-slopoly"></div>

## AI-assisted Slopoly malware powers Hive0163’s ransomware campaigns
IBM X-Force a identifié un nouveau malware nommé "Slopoly", utilisé par le groupe Hive0163. Ce script PowerShell présente des caractéristiques structurelles et des commentaires suggérant une génération via un modèle de langage (LLM). Slopoly agit comme un client C2 capable de collecter des données système, d'envoyer des "heartbeats" et de maintenir la persistance via des tâches planifiées. Le groupe Hive0163 utilise ce vecteur pour maintenir un accès à long terme lors d'attaques par ransomware Interlock. Cette évolution démontre comment l'IA agit comme un multiplicateur de force, permettant à des acteurs malveillants de créer rapidement des outils furtifs et personnalisés pour chaque cible.

**Analyse de l'impact** : Augmentation de la vitesse de développement des malwares et difficulté accrue pour les signatures antivirus traditionnelles.

**Recommandations** : 
*   Renforcer la surveillance de l'exécution de scripts PowerShell via le logging (Script Block Logging).
*   Surveiller la création de tâches planifiées inhabituelles via le processus `cmd.exe`.
*   Utiliser des solutions EDR basées sur le comportement plutôt que sur les signatures pour détecter les malwares "éphémères".

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Hive0163 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1059.001: PowerShell <br/> • T1053.005: Scheduled Task <br/> • T1588.006: Obtain Capabilities: AI-Assisted |
| Observables & Indicateurs de compromission | ```• Slopoly PowerShell script • FIRST_READ_ME.txt (Ransom note) • JunkFiction loader``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189378/malware/ai-assisted-slopoly-malware-powers-hive0163s-ransomware-campaigns.html

<br>
<br>

<div id="espionnage-russe-sur-les-messageries-chiffrees-signal-et-whatsapp"></div>

## Signal support : une vraie campagne d'espionnage russe
Une vaste campagne de phishing cible les utilisateurs des messageries Signal et WhatsApp en Europe, attribuée à des acteurs étatiques russes. Les attaquants envoient des messages se faisant passer pour le support technique de Signal, invoquant une "activité suspecte" pour inciter la victime à fournir un code de vérification SMS. Si le code est obtenu, le pirate peut lier le compte de la cible à son propre appareil (ordinateur ou tablette). Bien qu'ils ne puissent pas voir l'historique des messages passés, ils obtiennent l'accès aux contacts et peuvent usurper l'identité de la victime pour de nouvelles attaques de phishing. Une variante plus dangereuse utilise des QR codes pour tenter de récupérer l'historique des messages.

**Analyse de l'impact** : Risque d'espionnage de haut niveau et de compromission de la chaîne de confiance entre diplomates, militaires et journalistes.

**Recommandations** : 
*   Activer impérativement le "Verrouillage de l'enregistrement" (Registration Lock) et un code PIN sur Signal.
*   Ne jamais scanner de QR code envoyé par messagerie pour "vérifier" un compte.
*   Rappeler aux utilisateurs que le support de Signal ou WhatsApp ne demande jamais de codes de vérification par message.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteurs étatiques russes (probablement APT28 ou Sandworm) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1566: Phishing <br/> • T1098.002: Additional Cloud Credentials |
| Observables & Indicateurs de compromission | ```• Messages provenant de faux comptes "Signal Support" • Demandes de codes PIN/SMS inattendues``` |

### Source (url) du ou des articles
* https://www.lemonde.fr/pixels/article/2026/03/13/signal-support-un-faux-message-d-alerte-une-vraie-campagne-d-espionnage-des-utilisateurs-de-la-messagerie-attribuee-a-la-russie_6671046_4408996.html

<br>
<br>

<div id="vulnerabilite-critique-sql-injection-dans-le-plugin-wordpress-ally"></div>

## SQL Injection Vulnerability in Ally WordPress Plugin Exposes 200K+ Sites
Une vulnérabilité critique d'injection SQL (CVE-2026-2413) a été découverte dans le plugin WordPress "Ally", utilisé par plus de 400 000 sites. La faille permet à un attaquant non authentifié d'exécuter des requêtes SQL arbitraires via des paramètres URL mal filtrés. En utilisant des techniques de "Blind SQL injection" basées sur le temps, les attaquants peuvent extraire les condensés de mots de passe des administrateurs et les adresses e-mail de la base de données. Bien qu'un correctif (v4.1.0) ait été publié fin février, environ 60% des installations n'ont pas encore été mises à jour, laissant 200 000 sites vulnérables à des attaques automatisées.

**Analyse de l'impact** : Risque d'accès administrateur et de vol de données massifs sur les sites WordPress impactés.

**Recommandations** : 
*   Mettre à jour le plugin Ally vers la version 4.1.0 ou supérieure immédiatement.
*   Auditer les journaux d'accès web pour des requêtes suspectes contenant des clauses SQL (ex: `UNION SELECT`, `SLEEP`).
*   Utiliser un pare-feu applicatif web (WAF) avec des règles génériques de protection contre les injections SQL.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (vulnérabilité logicielle) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1190: Exploit Public-Facing Application |
| Observables & Indicateurs de compromission | ```• CVE-2026-2413 • Requêtes HTTP GET avec paramètres SQL injectés``` |

### Source (url) du ou des articles
* https://hackread.com/sql-injection-vulnerability-ally-wordpress-plugin/