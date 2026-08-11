# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [DeadLock ransomware : analyse d'un encryptor Rust avec infrastructure de récupération décentralisée](#deadlock-ransomware-analyse-dun-encryptor-rust-avec-infrastructure-de-recuperation-decentralisee)
  * [Aeternum : analyse d'un botnet loader utilisant la blockchain Polygon comme infrastructure C2 décentralisée](#aeternum-analyse-dun-botnet-loader-utilisant-la-blockchain-polygon-comme-infrastructure-c2-decentralisee)
  * [tl;dv : 181 874 réunions exposées par défaut d'isolation tenant sur Firestore](#tldv-181-874-reunions-exposees-par-defaut-disolation-tenant-sur-firestore)
  * [Malware 4 Noobs (Partie I) : introduction aux concepts de développement malware, stagers et LOLBINs](#malware-4-noobs-partie-i-introduction-aux-concepts-de-developpement-malware-stagers-et-lolbins)
  * [NoiseHound : scoring des chemins d'attaque BloodHound avec prise en compte de la détectabilité](#noisehound-scoring-des-chemins-dattaque-bloodhound-avec-prise-en-compte-de-la-detectabilite)
  * [Opérateur russophone : chaînage de CVE sur caméras et routeurs pour créer un pipeline proxy et de visualisation contre l'Ukraine](#operateur-russophone-chainage-de-cve-sur-cameras-et-routeurs-pour-creer-un-pipeline-proxy-et-de-visualisation-contre-lukraine)
  * [PyPsPipeJack : implémentation Python d'une technique de mouvement latéral et d'escalade de privilèges via PowerShell named pipes](#pypspipejack-implementation-python-dune-technique-de-mouvement-lateral-et-descalade-de-privileges-via-powershell-named-pipes)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La journée est marquée par un volume exceptionnel de 70 vulnérabilités, largement dominé par le Patch Tuesday de Microsoft (juin 2025) qui corrige 67 failles dont 9 critiques et 2 zero-days, dont CVE-2025-33053 activement exploitée. Des vulnérabilités critiques hors écosystème Microsoft retiennent également l'attention, notamment CVE-2025-5777 (CitrixBleed 2) sur NetScaler permettant le détournement de session sans authentification, et deux failles CVSS 10.0 sur Cisco ISE (CVE-2025-20281/20282) exposant à l'exécution de code à distance non authentifiée. En parallèle, 9 fuites de données significatives sont recensées, parmi lesquelles l'attaque contre l'assureur Aflac attribuée au groupe Scattered Spider, la compromission de 8,4 millions d'utilisateurs chez Zoomcar, et la fuite historique de 16 milliards d'identifiants issue de logs d'infostealers. L'absence totale de signaux sur les acteurs de menace, la géopolitique et la réglementation suggère une focalisation de l'écosystème sur la remédiation technique et la gestion d'incidents post-compromission. Les équipes SOC doivent prioriser le patching immédiat de Citrix NetScaler et Cisco ISE, dont l'exploitation non authentifiée présente un risque élevé de pivot initial. La masse d'identifiants exposés via infostealers accroît significativement le risque de prise de compte et de phishing ciblé dans les jours à venir. Une vigilance renforcée sur les secteurs assurance et santé, particulièrement visés, est recommandée.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

_Aucun acteur identifié._

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

_Aucun événement géopolitique._

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

_Aucune actualité réglementaire._

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Gouvernement / Immigration** | Israel Population and Immigration Authority | Numéros d'identification nationale, adresses, numéros de téléphone, dates de naissance et de décès, dates d'immigration, liens familiaux | 9200000 | [https://securityaffairs.com/196942/cyber-crime/9-2-million-israeli-records-sold-as-a-new-breach-are-20-years-old.html](https://securityaffairs.com/196942/cyber-crime/9-2-million-israeli-records-sold-as-a-new-breach-are-20-years-old.html) |
| **Logistique et transport** | Ceva Logistics | Noms, adresses postales, numéros de téléphone, adresses email, détails de commandes clients | Inconnu | [https://infosec.exchange/@beyondmachines1/117072991700624929](https://infosec.exchange/@beyondmachines1/117072991700624929)<br>[https://infosec.exchange/@suriq/117071874780704817](https://infosec.exchange/@suriq/117071874780704817)<br>[https://techcrunch.com/2026/08/10/a-data-breach-at-shipping-giant-ceva-logistics-is-rippling-across-banks-retailers-steam-gamers-and-beyond/](https://techcrunch.com/2026/08/10/a-data-breach-at-shipping-giant-ceva-logistics-is-rippling-across-banks-retailers-steam-gamers-and-beyond/) |
| **Multi-secteurs (santé, gouvernement, VPN, technologie)** | SplitVPN et multiples organisations (secteur santé et gouvernement) | Données variées selon les 28 incidents : enregistrements SplitVPN (865 336), données de santé, données gouvernementales, credentials et tokens potentiellement compromis via les failles exploitées | 1200000 | [https://infosec.exchange/@beyondmachines1/117072285595442089](https://infosec.exchange/@beyondmachines1/117072285595442089) |
| **Gouvernement, infrastructures critiques, organisations diverses** | Gunra Ransomware (CISA Advisory) | Données chiffrées et données exfiltrées (menace de publication sur DLS) | Inconnu | [https://databreaches.net/2026/08/10/cisa-advisory-stopransomware-gunra-ransomware/](https://databreaches.net/2026/08/10/cisa-advisory-stopransomware-gunra-ransomware/) |
| **Transport aérien** | Frontier Airlines | Données de passagers (détails non spécifiés) | Inconnu | [https://mastodon.au/@vibewire/117073728711972564](https://mastodon.au/@vibewire/117073728711972564) |
| **Services informatiques / IT** | TCS (Tata Consultancy Services) | Données employés (détails non spécifiés) | Inconnu | [https://mastodon.social/@EarthInsider/117073473410148536](https://mastodon.social/@EarthInsider/117073473410148536) |
| **Matériel informatique / Hardware** | Framework (entreprise informatique) | Données clients (détails non spécifiés) | Inconnu | [https://techhub.social/@techandcoffee/117073205921914899](https://techhub.social/@techandcoffee/117073205921914899) |
| **Défense / Manufacture** | IEH Corp | Données d'ingénierie sensibles et données contrôlées à l'export | Inconnu | [https://mastodon.social/@netsecio/117072020883105029](https://mastodon.social/@netsecio/117072020883105029) |
| **Santé / Technology** | Unlimited Technology Systems | Données personnelles (détails non spécifiés, potentiellement données de santé) | 3800000 | [https://mastodon.thenewoil.org/@thenewoil/117071688733178253](https://mastodon.thenewoil.org/@thenewoil/117071688733178253) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-15581** | 8.0 | N/A | FALSE | Red Hat OpenShift AI (RHOAI) | CWE-306 Missing Authentication for Critical Function | Accès non authentifié à l'API TAS permettant la lecture, la modification et la suppression de données de monitoring et de configurations. Possibilité d'injection de données arbitraires dans le service, pouvant perturber les opérations des tenants du cluster OpenShift AI. | Theoretical | Restreindre l'accès réseau au service TAS via des NetworkPolicies Kubernetes. Exiger l'authentification pour l'API backend TAS. Limiter l'accès réseau des pods. Revoir la sécurité du déploiement TAS. Appliquer les correctifs de Red Hat dès leur disponibilité. Consulter les ressources : hxxps[://]access[.]redhat[.]com/security/cve/CVE-2026-15581 et hxxps[://]bugzilla[.]redhat[.]com/show_bug[.]cgi?id=2499637 | [https://cvefeed.io/vuln/detail/CVE-2026-15581](https://cvefeed.io/vuln/detail/CVE-2026-15581) |
| **CVE-2025-30241** | 8.6 | N/A | FALSE | HB810(US2) V1.0/1.6/2.0/2.6, HB810(EU1) V2.0, HB710(US2) V1.6/1.0 | CWE-78 Improper neutralization of special elements used in an OS command ('OS command injection') | Exécution de commandes système arbitraires avec privilèges élevés, pouvant mener à une compromission complète du dispositif et un accès au réseau environnant. | Theoretical | Mettre à jour les dispositifs TP-Link Aginet avec le dernier firmware disponible. Restreindre l'accès à l'interface web. Sanitiser toutes les entrées utilisateur. Consulter : hxxps[://]www[.]tp-link[.]com/us/support/faq/5239/ | [https://cvefeed.io/vuln/detail/CVE-2025-30241](https://cvefeed.io/vuln/detail/CVE-2025-30241) |
| **CVE-2025-30239** | 8.5 | N/A | FALSE | HB810(US2) V1.0/1.6/2.0/2.6, HB810(EU1) V2.0, HB710(US2) V1.6/1.0 | CWE-321: Use of Hard-coded Cryptographic Key | Accès aux données de configuration sensibles déchiffrées, incluant des credentials et des informations de service, pouvant mener à une compromission du dispositif et du réseau. | Theoretical | Mettre à jour le firmware à la dernière version. Éviter l'utilisation de clés cryptographiques codées en dur. Implémenter des pratiques de gestion sécurisée des clés. Revoir et sécuriser les données sensibles stockées. Consulter : hxxps[://]www[.]tp-link[.]com/us/support/faq/5239/ | [https://cvefeed.io/vuln/detail/CVE-2025-30239](https://cvefeed.io/vuln/detail/CVE-2025-30239) |
| **CVE-2025-30238** | 8.6 | N/A | FALSE | HB810(US2) V1.0/1.6/2.0/2.6, HB810(EU1) V2.0, HB710(US2) V1.6/1.0 | CWE-863: Incorrect Authorization | Élévation de privilèges permettant la création de comptes administrateurs et la modification de configurations critiques, menant à une compromission complète du dispositif. | Theoretical | Mettre à jour le firmware à la dernière version. Revoir et restreindre les privilèges des utilisateurs. Surveiller le système pour détecter les modifications non autorisées. Consulter : hxxps[://]www[.]tp-link[.]com/us/support/faq/5239/ | [https://cvefeed.io/vuln/detail/CVE-2025-30238](https://cvefeed.io/vuln/detail/CVE-2025-30238) |
| **CVE-2025-30237** | 8.7 | N/A | FALSE | HB810(US2) V1.0/1.6/2.0/2.6, HB810(EU1) V2.0, HB710(US2) V1.6/1.0 | CWE-862: Missing Authorization | Un attaquant non authentifié peut exécuter des opérations privilégiées et obtenir le contrôle complet du dispositif, permettant potentiellement le pivot vers le réseau interne. | Theoretical | Mettre à jour le firmware à la dernière version. Appliquer l'authentification de manière cohérente sur tous les endpoints de l'interface web. Valider les credentials utilisateur sur toutes les requêtes. Implémenter une gestion robuste des sessions. Consulter : hxxps[://]www[.]tp-link[.]com/us/support/faq/5239/ | [https://cvefeed.io/vuln/detail/CVE-2025-30237](https://cvefeed.io/vuln/detail/CVE-2025-30237) |
| **CVE-2026-18577** | 8.2 | 4.10% | TRUE | N-central | CWE-288 Authentication bypass using an alternate path or channel | Compromission complète du serveur N-central permettant l'accès à tous les appareils gérés (jusqu'à 24 000 par serveur). Déploiement de ransomware StormEncryptor, exfiltration de données, vol de credentials via Mimikatz, et mouvement latéral via outils RMM. Impact potentiellement massif sur les clients des MSP affectés. | Active | Appliquer immédiatement les hotfix de N-able pour CVE-2026-18577 et CVE-2026-18556. Restreindre l'exposition Internet des serveurs N-central. Surveiller les accès administratifs. Révoquer et réinitialiser tous les credentials après application des correctifs. Mettre en place un accès VPN pour atteindre N-central. Désinstaller ou surveiller les outils RMM non autorisés (AnyDesk, SimpleHelp). | [https://thehackernews.com/2026/08/china-linked-hackers-deploy-new.html](https://thehackernews.com/2026/08/china-linked-hackers-deploy-new.html)<br>[https://www.security.nl/posting/948726/Microsoft+vermoedt+dat+criminelen+ransomware+verspreiden+via+N-Central-lek?channel=rss](https://www.security.nl/posting/948726/Microsoft+vermoedt+dat+criminelen+ransomware+verspreiden+via+N-Central-lek?channel=rss) |
| **CVE-2026-4793** | 7.3 | 0.13% | FALSE | Synology Assistant | CWE-276 Incorrect Default Permissions | Atteinte à la confidentialité des données, atteinte à l'intégrité des données, déni de service | None | Se référer au bulletin de sécurité de l'éditeur Synology (Synology_SA_26_12) pour l'obtention des correctifs et mettre à jour vers la version 7.0.7-50095 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0988/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0988/)<br>[https://www.synology.com/en-global/security/advisory/Synology_SA_26_12](https://www.synology.com/en-global/security/advisory/Synology_SA_26_12) |
| **CVE-2026-33377** | 7.1 | 0.23% | FALSE | Grafana OSS | Élévation de privilèges / Contournement de politique de sécurité | Élévation de privilèges, contournement de la politique de sécurité | None | Se référer au bulletin de sécurité HPE Aruba Networking (HPESBNW05119) pour l'obtention des correctifs et mettre à jour vers la version 1.26.1.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0989/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0989/)<br>[https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05119.txt](https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05119.txt) |
| **CVE-2026-54763** | 7.8 | 0.21% | FALSE | traefik | CWE-178: Improper Handling of Case Sensitivity | Élévation de privilèges, contournement de la politique de sécurité | None | Se référer au bulletin de sécurité HPE Aruba Networking (HPESBNW05119) pour l'obtention des correctifs et mettre à jour vers la version 1.26.1.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0989/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0989/)<br>[https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05119.txt](https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05119.txt) |
| **CVE-2026-66151** | N/A | 0.16% | FALSE | Global VPN Client | CWE-125 Out-of-bounds read | Déni de service | None | Se référer au bulletin de sécurité SonicWall (SNWLID-2026-0010) pour l'obtention des correctifs et mettre à jour vers la version 5.0.0.2008 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0990/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0990/)<br>[https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0010](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0010) |
| **CVE-2018-11798** | N/A | 4.88% | FALSE | Apache Thrift | Improper Access Control | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2019-0205** | N/A | 9.16% | FALSE | Apache Thrift | Potential DoS when processing untrusted Thrift payloads | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2020-13949** | N/A | 6.78% | FALSE | Apache Thrift | Potential DoS when processing untrusted Thrift payloads | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-43869** | 7.3 | 0.63% | FALSE | Apache Thrift | CWE-297 Improper Validation of Certificate with Host Mismatch | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-45205** | 5.3 | 0.47% | FALSE | Apache Commons Configuration | CWE-674 Uncontrolled Recursion | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-54291** | 8.2 | 0.20% | FALSE | pgjdbc | CWE-636: Not Failing Securely ('Failing Open') | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-55831** | 7.5 | 0.42% | FALSE | netty | CWE-770: Allocation of Resources Without Limits or Throttling | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-55833** | 7.5 | 0.42% | FALSE | netty | CWE-400: Uncontrolled Resource Consumption | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-56745** | 8.7 | 0.61% | FALSE | netty | CWE-400: Uncontrolled Resource Consumption | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-56746** | 6.5 | 0.38% | FALSE | netty | CWE-284: Improper Access Control | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-56819** | 7.5 | 0.36% | FALSE | netty | CWE-400: Uncontrolled Resource Consumption | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-59898** | 6.3 | 0.25% | FALSE | netty | CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-59899** | 6.9 | 0.34% | FALSE | netty | CWE-770: Allocation of Resources Without Limits or Throttling | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-59900** | 6.9 | 0.23% | FALSE | netty | CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-59901** | 8.7 | 0.26% | FALSE | netty | CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop') | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2026-59921** | 5.7 | 0.47% | FALSE | netty | CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') | Problème de sécurité non spécifié par l'éditeur | None | Se référer au bulletin de sécurité VMware (38158) pour l'obtention des correctifs et mettre à jour vers la version 8.0.3 ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0991/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38158) |
| **CVE-2025-8088** | 8.4 | 94.55% | TRUE | WinRAR | CWE-35 Path traversal | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20337** | 7.5 | 0.36% | FALSE | Cisco Secure Endpoint | CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20338** | 7.5 | 0.33% | FALSE | Cisco Secure Endpoint | CWE-415 Double Free | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20339** | 7.5 | 0.33% | FALSE | Cisco Secure Endpoint | CWE-190 Integer Overflow or Wraparound | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20345** | 7.5 | 0.33% | FALSE | Cisco Secure Endpoint | CWE-121 Stack-based Buffer Overflow | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20346** | 7.5 | 0.33% | FALSE | Cisco Secure Endpoint | CWE-125 Out-of-bounds Read | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20347** | 7.5 | 0.33% | FALSE | Cisco Secure Endpoint | CWE-125 Out-of-bounds Read | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-20348** | N/A | 0.33% | FALSE | ClamAV versions 1.5.x antérieures à 1.5.4 et versions antérieures à 1.4.6 | Non spécifiée | Atteinte à la confidentialité des données, déni de service, problème de sécurité non spécifié | None | Mettre à jour ClamAV vers la version 1.5.4 (branche 1.5.x) ou 1.4.6 (branche 1.4.x) selon la version utilisée. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0992/)<br>[https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html) |
| **CVE-2026-8718** | 8.4 | N/A | FALSE | zephyr | CWE-787 bounds | Débordement de tampon heap noyau pouvant potentiellement mener à une exécution de code ou un crash du système. Le contenu débordant est contrôlé par le pair distant via le CID DTLS. | Theoretical | Appliquer le correctif qui rejette les appels dont optlen est inférieur à MBEDTLS_SSL_CID_OUT_LEN_MAX avec -EINVAL. S'assurer que les configurations DTLS Connection ID sont sécurisées. Désactiver CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID si non nécessaire. | [https://cvefeed.io/vuln/detail/CVE-2026-8718](https://cvefeed.io/vuln/detail/CVE-2026-8718)<br>[https://github.com/zephyrproject-rtos/zephyr/commit/aa317825a55a401315e8e17f620c70c02e8f176d](https://github.com/zephyrproject-rtos/zephyr/commit/aa317825a55a401315e8e17f620c70c02e8f176d)<br>[https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-p3r6-mx6c-33gq](https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-p3r6-mx6c-33gq) |
| **CVE-2026-48161** | 9.3 | N/A | FALSE | react18-use | CWE-506: Embedded Malicious Code | Compromission complète des machines de développement ayant exécuté `npm install` contre un checkout affecté. Le payload de second stade était hébergé par l'attaquant et ne peut être reconstitué. Considérer que tout ce qui est accessible depuis un processus Node avec les permissions de l'utilisateur est compromis. | Active | Supprimer les commits malveillants et src/install[.]js des clones locaux. Jeter les clones locaux du dépôt. Réinitialiser tous les identifiants et auditer l'activité des comptes depuis le 2026-05-19 01:07:01. Considérer les machines affectées comme compromises et effectuer une investigation forensique complète. | [https://cvefeed.io/vuln/detail/CVE-2026-48161](https://cvefeed.io/vuln/detail/CVE-2026-48161)<br>[https://github.com/dai-shi/react18-use/security/advisories/GHSA-32xh-vg5f-64fm](https://github.com/dai-shi/react18-use/security/advisories/GHSA-32xh-vg5f-64fm) |
| **CVE-2026-73030** | 7.2 | N/A | FALSE | unearth | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Écriture arbitraire de fichiers sur le système de fichiers, pouvant mener à une exécution de code ou une corruption de données selon l'emplacement d'écriture. | Theoretical | Mettre à jour unearth vers une version incluant les correctifs de sécurité (commit 6c78164 ou supérieur). Éviter de traiter des archives non fiables avec unearth. Normaliser les chemins avant validation dans les implémentations personnalisées. | [https://cvefeed.io/vuln/detail/CVE-2026-73030](https://cvefeed.io/vuln/detail/CVE-2026-73030)<br>[https://github.com/frostming/unearth/commit/6c78164e7bfa28b8b3d6f247b87e560692e3c8ba](https://github.com/frostming/unearth/commit/6c78164e7bfa28b8b3d6f247b87e560692e3c8ba)<br>[https://github.com/frostming/unearth/issues/180](https://github.com/frostming/unearth/issues/180)<br>[https://github.com/frostming/unearth/pull/181](https://github.com/frostming/unearth/pull/181)<br>[https://www.vulncheck.com/advisories/unearth-path-traversal-via-unnormalized-paths-and-symlink-escape](https://www.vulncheck.com/advisories/unearth-path-traversal-via-unnormalized-paths-and-symlink-escape) |
| **CVE-2026-72911** | 9.9 | N/A | FALSE | erpnext | CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine | Exécution de code arbitraire côté serveur (RCE) par un utilisateur authentifié avec un rôle opérationnel standard. Accès en lecture à l'ensemble des données de l'application. Score CVSS 3.1 : 9.9 (CRITICAL). | Theoretical | Mettre à jour ERPNext vers la version 15.118.0 ou 16.29.0. Restreindre l'accès au module process_statement_of_accounts. Surveiller les journails d'exécution de templates. | [https://cvefeed.io/vuln/detail/CVE-2026-72911](https://cvefeed.io/vuln/detail/CVE-2026-72911)<br>[https://github.com/frappe/erpnext/security/advisories/GHSA-qq49-v74j-hjh7](https://github.com/frappe/erpnext/security/advisories/GHSA-qq49-v74j-hjh7) |
| **CVE-2026-72904** | 9.3 | N/A | FALSE | firecrawl | CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') | Lecture arbitraire de fichiers sur le serveur, pouvant exposer des secrets, des configurations et des données sensibles. Score CVSS 4.0 : 9.3 (CRITICAL). | Theoretical | Mettre à jour Firecrawl vers la version 2.11.32 ou ultérieure. Restreindre l'accès à l'API d'extraction. Désactiver la résolution de références externes dans json-schema-ref-parser. | [https://cvefeed.io/vuln/detail/CVE-2026-72904](https://cvefeed.io/vuln/detail/CVE-2026-72904) |
| **CVE-2026-72903** | 8.1 | N/A | FALSE | tabby | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Écriture ou écrasement de fichiers arbitraires en dehors du répertoire de téléchargement sélectionné par l'utilisateur, pouvant mener à l'exécution de code ou à la corruption de fichiers système. Score CVSS 3.1 : 8.1 (HIGH). | Theoretical | Mettre à jour Tabby vers la version 1.0.235 ou ultérieure. Vérifier le traitement des noms de fichiers SFTP. Éviter les connexions vers des serveurs SFTP non fiables. | [https://cvefeed.io/vuln/detail/CVE-2026-72903](https://cvefeed.io/vuln/detail/CVE-2026-72903)<br>[https://github.com/Eugeny/tabby/security/advisories/GHSA-59p9-8gwf-v9v7](https://github.com/Eugeny/tabby/security/advisories/GHSA-59p9-8gwf-v9v7) |
| **CVE-2026-48160** | 9.3 | N/A | FALSE | react-tracked | CWE-506: Embedded Malicious Code | Compromission complète des machines de développement ayant exécuté `npm install` contre un checkout affecté. Le payload de second stade étant hébergé par l'attaquant, l'étendue exacte de la compromission ne peut être déterminée. Il faut supposer une compromission totale de tout ce qui est accessible depuis un processus Node avec les permissions de l'utilisateur. Score CVSS 4.0 : 9.3 (CRITICAL). | Active | Supprimer les commits malveillants des clones locaux. Auditer l'activité des comptes depuis le 2026-05-18 19:26:36. Rotationner tous les credentials accessibles par la machine. Réinstaller les dépendances depuis une source de confiance. | [https://cvefeed.io/vuln/detail/CVE-2026-48160](https://cvefeed.io/vuln/detail/CVE-2026-48160)<br>[https://github.com/dai-shi/react-tracked/security/advisories/GHSA-79c5-q7m9-9c6x](https://github.com/dai-shi/react-tracked/security/advisories/GHSA-79c5-q7m9-9c6x) |
| **CVE-2026-18478** | 5.1 | N/A | FALSE | Magnolia CMS | CWE-79 Improper neutralization of input during web page generation ('cross-site scripting') | Exécution de code JavaScript arbitraire dans le contexte de session d'autres utilisateurs (potentiellement des administrateurs), pouvant mener à un vol de session, une élévation de privilèges ou une exfiltration de données. | Theoretical | Mettre à jour Magnolia CMS vers la version 6.3.10 ou ultérieure. Restreindre les privilèges éditeur. Valider et sanitiser les noms de fichiers lors de l'import. | [https://cert.pl/en/posts/2026/08/CVE-2026-18478/](https://cert.pl/en/posts/2026/08/CVE-2026-18478/) |
| **CVE-2026-34348** | 6.5 | 0.71% | FALSE | Windows 10 Version 1809, Windows 10 Version 21H2, Windows 10 Version 22H2 | CWE-693: Protection Mechanism Failure | Usurpation d'identité d'utilisateurs privilégiés contournant les politiques de MFA résistant au phishing. Accès non autorisé à des ressources et données sensibles via Microsoft Entra ID. | Theoretical | Appliquer les mises à jour de sécurité Microsoft pour CVE-2026-34348. Adopter une approche Zero Trust et least-privilege. Maintenir les protections endpoint. Surveiller les authentifications Entra ID pour des comportements anormaux. | [https://thehackernews.com/2026/08/new-passkey-attacks-can-recover-synced.html](https://thehackernews.com/2026/08/new-passkey-attacks-can-recover-synced.html) |
| **CVE-2026-18370** | 4.8 | N/A | FALSE | entr | CWE-122 Heap-based buffer overflow | Corruption mémoire, arrêt de processus et déni de service par un attaquant local. Potentielle exécution de code arbitraire selon le contexte d'exploitation. | Theoretical | Appliquer le commit 2467fe0 ou mettre à jour vers une version supérieure à 5.8. Limiter la longueur des arguments passés à entr. Surveiller les crashes du processus. | [https://cert.pl/en/posts/2026/08/CVE-2026-18370/](https://cert.pl/en/posts/2026/08/CVE-2026-18370/) |
| **CVE-2026-3502** | 7.8 | 5.75% | TRUE | TrueConf Client | CWE-494: Download of Code Without Integrity Check. | Compromission de systèmes exécutant TrueConf Client via exploitation zero-day, ciblant des entités gouvernementales d'Asie du Sud-Est. | Active | Mettre à jour TrueConf Client avec la dernière version corrigée. Surveiller les activités suspectes liées au client TrueConf. | [https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html](https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html) |
| **CVE-2026-66484** | 4.6 | N/A | FALSE | cpio | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Permet à un attaquant de créer des liens physiques vers des fichiers arbitraires en dehors du répertoire d'extraction prévu, pouvant mener à une corruption de fichiers ou un accès non autorisé. | None | Appliquer le correctif (commit e2b9cbdd3354d2b1569b7390d1bc15c1930559ad). Éviter d'extraire des archives non fiables avec cpio. | [https://cert.pl/en/posts/2026/08/CVE-2026-66484/](https://cert.pl/en/posts/2026/08/CVE-2026-66484/) |
| **CVE-2026-66485** | 4.6 | N/A | FALSE | cpio | CWE-789 Memory allocation with excessive size value | Déni de service – crash du processus cpio lors de l'extraction d'une archive malveillante. | None | Appliquer le correctif (commit 3cd514031371d8aeeaf2048aa10103e02831aaa9). Éviter d'extraire des archives cpio non fiables. | [https://cert.pl/en/posts/2026/08/CVE-2026-66484/](https://cert.pl/en/posts/2026/08/CVE-2026-66484/) |
| **CVE-2026-66486** | 4.6 | N/A | FALSE | cpio | CWE-116 Improper Encoding or Escaping of Output | Falsification de listes d'archives et injection de séquences de contrôle terminal, pouvant tromper les utilisateurs ou automatiser des actions via terminal. | None | Appliquer le correctif (commit 2ff9600c9ef32e88759843cdbde74c8db5ae9b30). Éviter d'afficher des listes d'archives non fiables. | [https://cert.pl/en/posts/2026/08/CVE-2026-66484/](https://cert.pl/en/posts/2026/08/CVE-2026-66484/) |
| **CVE-2026-71391** | 5.3 | N/A | FALSE | Emacs | CWE-193 Off-by-one Error | Exposition du contenu de la mémoire du tas, pouvant être utilisée pour contourner ASLR et faciliter des attaques ultérieures. | None | Appliquer le correctif (commit 95ab9ef627b212d74d321c5bbb5b56a1be7b9fbe). Éviter de charger des polices TrueType non fiables dans Emacs. | [https://cert.pl/en/posts/2026/08/CVE-2026-71391/](https://cert.pl/en/posts/2026/08/CVE-2026-71391/) |
| **CVE-2026-71392** | 5.3 | N/A | FALSE | Emacs | CWE-190 Integer Overflow or Wraparound | Corruption de la mémoire du tas pouvant mener à l'exécution de code arbitraire. | None | Appliquer le correctif (commit c4e20777c26548722a37b03db93243e83a0d6188). Éviter de charger des polices TrueType non fiables. | [https://cert.pl/en/posts/2026/08/CVE-2026-71391/](https://cert.pl/en/posts/2026/08/CVE-2026-71391/) |
| **CVE-2026-71393** | 5.3 | N/A | FALSE | Emacs | CWE-190 Integer Overflow or Wraparound | Corruption de la mémoire du tas pouvant mener à l'exécution de code arbitraire. | None | Appliquer le correctif (commit d51a4722316efe0960994d371e1859099894d1ca). Éviter de charger des polices TrueType non fiables. | [https://cert.pl/en/posts/2026/08/CVE-2026-71391/](https://cert.pl/en/posts/2026/08/CVE-2026-71391/) |
| **CVE-2026-71394** | 5.3 | N/A | FALSE | Emacs | CWE-1284 Improper Validation of Specified Quantity in Input | Utilisation de données tas non initialisées dans les recherches de tables ultérieures, pouvant entraîner une divulgation d'informations, des crashes ou un accès mémoire arbitraire sur les cibles 32 bits. | None | Appliquer le correctif (commit 7621ee1d01229d50e5c0cddea6bf0b01095a62cf). Éviter de charger des polices TrueType non fiables. | [https://cert.pl/en/posts/2026/08/CVE-2026-71391/](https://cert.pl/en/posts/2026/08/CVE-2026-71391/) |
| **CVE-2026-8037** | 9.6 | 99.31% | TRUE | LoadMaster, ECS Connections Manager, Object Scale Connection Manager | CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') | Compromission totale des load balancers LoadMaster par un attaquant non authentifié, permettant l'exécution de commandes système, le pivot réseau, et potentiellement l'interception ou la manipulation du trafic load balancé. | Active | Appliquer immédiatement les mises à jour Progress Kemp LoadMaster disponibles depuis début juin 2026. Restreindre l'accès aux interfaces d'administration. Consulter le bulletin de sécurité Progress (CVE-2026-8037 / CVE-2026-33691). | [https://www.security.nl/posting/948652/Kritiek+lek+in+Progress+Kemp+LoadMaster-loadbalancers+actief+misbruikt?channel=rss](https://www.security.nl/posting/948652/Kritiek+lek+in+Progress+Kemp+LoadMaster-loadbalancers+actief+misbruikt?channel=rss) |
| **CVE-2024-1212** | 10.0 | 95.39% | TRUE | LoadMaster | CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Compromission des load balancers LoadMaster (historique). | Active | S'assurer que les correctifs pour CVE-2024-1212 sont appliqués sur toutes les instances LoadMaster. | [https://www.security.nl/posting/948652/Kritiek+lek+in+Progress+Kemp+LoadMaster-loadbalancers+actief+misbruikt?channel=rss](https://www.security.nl/posting/948652/Kritiek+lek+in+Progress+Kemp+LoadMaster-loadbalancers+actief+misbruikt?channel=rss) |
| **CVE-2026-12537** | 10.0 | 0.15% | FALSE | Gemini CLI, run-gemini-cli GitHub Action | CWE-20 Improper Input Validation | Exécution de code arbitraire et vol de clés API dans les environnements d'automatisation utilisant Gemini CLI. | None | Mettre à jour Gemini CLI vers la dernière version corrigée. Révoquer et réémettre les clés API. Renforcer la gestion des secrets. | [https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/](https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/) |
| **CVE-2026-54316** | 6.0 | 0.40% | FALSE | claude-code | CWE-183: Permissive List of Allowed Inputs | Exécution de code arbitraire et vol de clés API dans les environnements d'automatisation utilisant Claude Code. | None | Mettre à jour Claude Code vers la dernière version corrigée. Révoquer et réémettre les clés API. Renforcer la gestion des secrets. | [https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/](https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/) |
| **CVE-2026-64638** | 8.9 | 0.77% | FALSE | WordPress | CWE-79 Cross-site Scripting (XSS) - Reflected | Exécution de scripts malveillants dans le navigateur des utilisateurs via XSS pré-authentification, pouvant escalader en RCE sur le serveur WordPress. | None | Mettre à jour WordPress vers la version 7.0.3. Appliquer les correctifs rétroportés pour les branches supportées. Déployer un WAF avec des règles de protection XSS. | [https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/](https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/) |
| **CVE-2026-65617** | 8.8 | 0.31% | FALSE | artifactory | CWE-502 Deserialization of Untrusted Data | Compromission initiale de l'environnement d'évaluation OpenAI via Artifactory, servant de point d'entrée à une campagne d'intrusion à grande échelle contre Hugging Face. | Active | Appliquer les correctifs Artifactory. Réduire les trust relationships héritées entre environnements. Mettre en place une défense en couches limitant la propagation d'un compromis initial. | [https://www.recordedfuture.com/blog/hugging-face-cheap-persistence](https://www.recordedfuture.com/blog/hugging-face-cheap-persistence) |
| **CVE-2026-65923** | 6.8 | 0.19% | FALSE | artifactory | CWE-918 Server-Side Request Forgery (SSRF) | Compromission de l'environnement d'évaluation OpenAI et pivot vers Hugging Face. | Active | Appliquer les correctifs Artifactory. Réduire les trust relationships héritées. Mettre en place une défense en couches. | [https://www.recordedfuture.com/blog/hugging-face-cheap-persistence](https://www.recordedfuture.com/blog/hugging-face-cheap-persistence) |
| **CVE-2026-66018** | 6.5 | 0.23% | FALSE | artifactory | CWE-200 Exposure of Sensitive Information to an Unauthorized Actor | Compromission de l'environnement d'évaluation OpenAI et pivot vers Hugging Face. | Active | Appliquer les correctifs Artifactory. Réduire les trust relationships héritées. Mettre en place une défense en couches. | [https://www.recordedfuture.com/blog/hugging-face-cheap-persistence](https://www.recordedfuture.com/blog/hugging-face-cheap-persistence) |
| **CVE-2026-33825** | 7.8 | 6.75% | TRUE | Microsoft Defender Antimalware Platform | CWE-1220: Insufficient Granularity of Access Control | Escalade de privilèges locale permettant aux attaquants d'élever leurs privilèges et de faciliter le déploiement de ransomware sur les systèmes compromis. | Active | Appliquer le correctif Microsoft publié le 14 avril 2026. Surveiller les activités d'escalade de privilèges. Maintenir une veille sur le catalogue KEV de CISA. | [https://securelist.com/malware-report-q2-2026-pc-iot-statistics/120960/](https://securelist.com/malware-report-q2-2026-pc-iot-statistics/120960/) |
| **CVE-2026-50751** | N/A | 82.55% | FALSE | Check Point Remote Access VPN et Mobile Access | Vulnérabilité critique (zero-day exploitée dans la nature) | Compromission initiale via le VPN permettant le déploiement de ransomware Qilin, chiffrement des données et extorsion. | Active | Appliquer les correctifs Check Point pour CVE-2026-50751. Restreindre l'accès aux interfaces VPN. Surveiller les connexions anormales. | [https://securelist.com/malware-report-q2-2026-pc-iot-statistics/120960/](https://securelist.com/malware-report-q2-2026-pc-iot-statistics/120960/) |
| **CVE-2026-50752** | 7.4 | 4.55% | FALSE | Quantum Security Gateway, Spark Firewalls | CWE-295: Improper Certificate Validation. | Contournement potentiel de l'authentification des connexions VPN site-to-site utilisant IKEv1, permettant des connexions non autorisées. | Theoretical | Appliquer les correctifs Check Point. Migrer d'IKEv1 vers IKEv2. Renouveler les certificats VPN site-to-site. | [https://securelist.com/malware-report-q2-2026-pc-iot-statistics/120960/](https://securelist.com/malware-report-q2-2026-pc-iot-statistics/120960/) |
| **CVE-2026-66738** | 7.7 | N/A | FALSE | SPIP | CWE-94 Improper Control of Generation of Code ('Code Injection') | Exécution de code à distance par des éditeurs authentifiés, pouvant mener à une compromission totale du serveur hébergeant SPIP. | None | Mettre à jour SPIP vers la version 4.4.18 ou supérieure dès que disponible. Isoler les instances non patchées. Restreindre l'accès aux comptes éditeurs. | [https://mastodon.social/@hugovalters/117073701052682697](https://mastodon.social/@hugovalters/117073701052682697) |
| **CVE-2026-47754** | 9.3 | N/A | FALSE | metacat | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Un attaquant non authentifié peut lire des fichiers arbitraires sur le serveur, ce qui peut entraîner l'exfiltration de données sensibles (fichiers de configuration, credentials, clés privées) et potentiellement faciliter des attaques ultérieures. | Theoretical | Désactiver immédiatement l'exposition publique des instances Metacat vulnérables. Restreindre l'accès via VPN ou liste blanche d'IP. Déployer un WAF avec filtrage des séquences de path traversal. Surveiller les journaux d'accès. Appliquer le correctif dès sa disponibilité. | [https://mastodon.social/@hugovalters/117072550822098454](https://mastodon.social/@hugovalters/117072550822098454)<br>[https://www.valtersit.com/cve/CVE-2026-47754/](https://www.valtersit.com/cve/CVE-2026-47754/) |
| **CVE-2026-60004** | N/A | N/A | FALSE | Forgejo (basé sur Gitea) - versions antérieures à v15 LTS et v16 | Exécution de code à distance (RCE) via endpoint diffpatch | Exécution de code à distance non authentifiée (après création de compte si inscriptions ouvertes) permettant le déploiement de crypto-miners, potentiellement des reverse shells ou des outils de mouvement latéral. Dans le cas documenté, l'impact s'est limité à un crypto-miner sans mouvement latéral détecté. | Active | Mettre à jour Forgejo vers v15 LTS ou v16. Désactiver les inscriptions ouvertes. Désactiver l'authentification locale au profit d'une authentification fédérée. Restreindre les connexions sortantes des conteneurs. Surveiller les appels à l'endpoint diffpatch. Maintenir les sauvegardes 3-2-1. | [https://social.lol/@phillip/117072545215119586](https://social.lol/@phillip/117072545215119586)<br>[https://phunky.cafe/my-homelab-got-hacked/](https://phunky.cafe/my-homelab-got-hacked/) |
| **CVE-2026-68121** | N/A | N/A | FALSE | Linux | Use-after-free via reallocation d'en-tête skb | Un attaquant local pourrait exploiter cette vulnérabilité pour provoquer une corruption mémoire menant potentiellement à une élévation de privilèges (exécution de code en ring 0) ou à un déni de service (kernel panic). | Theoretical | Désactiver ou restreindre le module PPPoE kernel si non nécessaire. Filtrer le trafic PPPoE au niveau du pare-feu. Surveiller les journaux kernel pour des anomalies liées à pppoe_sendmsg. Appliquer la mise à jour kernel corrective dès sa disponibilité. | [https://mastodon.social/@hugovalters/117072332979193830](https://mastodon.social/@hugovalters/117072332979193830)<br>[https://www.valtersit.com/cve/CVE-2026-68121/](https://www.valtersit.com/cve/CVE-2026-68121/) |
| **** | N/A | N/A | FALSE | Roundcube Webmail versions 1.6.x antérieures à 1.6.18 et versions 1.7.x antérieures à 1.7.3 | Multiples vulnérabilités (RCE, XSS, SSRF, contournement de politique de sécurité, atteinte à la confidentialité) | Exécution de code arbitraire à distance, atteinte à la confidentialité des données, falsification de requêtes côté serveur (SSRF), injection de code indirecte (XSS) et contournement de la politique de sécurité. Compromission potentielle du serveur de messagerie et des données des utilisateurs. | Theoretical | Se référer au bulletin de sécurité de l'éditeur et appliquer les mises à jour vers Roundcube Webmail 1.6.18 ou 1.7.3. Consulter : hxxps[://]roundcube[.]net/news/2026/08/09/security-updates-1[.]6[.]18-and-1[.]7[.]3 | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0987/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0987/) |
| **KLCERT-26-057** | N/A | N/A | FALSE | TrueConf Server (versions 5.3.x ≤ 5.3.9, 5.4.x ≤ 5.4.9, 5.5.x ≤ 5.5.5 et antérieures) | Exécution de code arbitraire avec privilèges élevés (chaîne d'exploitation) | Compromission totale du serveur TrueConf avec privilèges SYSTEM, permettant le déploiement de web shells, le vol d'identifiants (dump lsass), l'exfiltration de données et l'empoisonnement des installateurs clients (attaque de la chaîne d'approvisionnement). | Active | Mettre à jour TrueConf Server vers les versions 5.3.9, 5.4.9 ou 5.5.5 publiées le 18 juin 2026. Restreindre l'accès au port TCP 4307. Surveiller les modifications de fichiers dans le répertoire public/js. | [https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html](https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html) |
| **KLCERT-26-058** | N/A | N/A | FALSE | TrueConf Server (versions 5.3.x ≤ 5.3.9, 5.4.x ≤ 5.4.9, 5.5.x ≤ 5.5.5 et antérieures) | Évasion d'environnement isolé / Exécution de code arbitraire avec privilèges SYSTEM | Évasion de sandbox menant à une compromission complète du serveur avec privilèges SYSTEM, déploiement de web shells, vol de données et empoisonnement de la chaîne d'approvisionnement logicielle. | Active | Mettre à jour TrueConf Server vers les versions corrigées (5.3.9, 5.4.9, 5.5.5 – 18 juin 2026). Restreindre l'accès au port TCP 4307 et surveiller les activités suspectes. | [https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html](https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="deadlock-ransomware-analyse-dun-encryptor-rust-avec-infrastructure-de-recuperation-decentralisee"></div>

## DeadLock ransomware : analyse d'un encryptor Rust avec infrastructure de récupération décentralisée

### Résumé

Microsoft Threat Intelligence publie une analyse technique détaillée du ransomware DeadLock, un encryptor écrit en Rust observé depuis juillet 2025. DeadLock pratique la double extortion et a publié plus de 80 organisations compromises sur son site de leak, avec plus de la moitié des victimes en Europe. L'encryptor utilise un chiffrement hybride Curve25519/XChaCha20 avec une clé publique embarquée (03bf50bb...). Il implémente un geofencing linguistique (exclusion Russie, Ukraine, Biélorussie, etc.), un mécanisme de throttling basé sur les ressources système (CPU < 70%, mémoire < 29%), une stratégie de chiffrement partiel par taille de fichier (100% < 50MB, 50% < 118MB, 25% < 500MB, 10% < 1GB, chunked au-delà), et vide les journaux d'événements Windows via trois méthodes complémentaires. Sa particularité majeure est son infrastructure de récupération décentralisée : un fichier HTML RECOVERY_CHAT auto-contenu qui interroge des smart contracts Polygon pour récupérer l'URL du proxy, communique via le réseau Session (messenger onion-routed) pour le chat victime-opérateur, et héberge les données de leak sur Wasabi (S3-compatible). DeadLock est déployé par des affiliés des écosystèmes Lynx et INC ransomware.

---

### Analyse opérationnelle

L'encryptor DeadLock présente plusieurs défis de détection pour les équipes SOC : (1) Le throttling basé sur les ressources maintient une consommation CPU/mémoire normale, rendant la détection comportementale plus difficile ; (2) Le chiffrement partiel intermittent (blocs de 512 octets à intervalles réguliers) accélère l'impact tout en rendant les fichiers inutilisables ; (3) L'effacement des journaux d'événements via trois méthodes (API EventLog, manipulation registre WINEVT\Channels, wevtapi.dll) complique l'investigation forensique post-incident ; (4) L'infrastructure décentralisée (Polygon blockchain + Session messenger) rend les takedowns traditionnels inefficaces car il n'y a pas de domaine central à saisir ; (5) La terminaison de processus de sécurité (msmpeng, smartscreen) et la désactivation de services (windefend, vss, wbengine, Hyper-V, AD) nécessitent une protection tamper-proof préalable. Les équipes doivent surveiller les requêtes vers les endpoints RPC Polygon publics, la création de fichiers .dlock, et les modifications de clés registre WINEVT. Microsoft fournit des détections Defender (Ransom:Win32/Deadlock.*) et recommande l'activation de Controlled Folder Access, EDR en mode bloc, et les règles ASR.

---

### Implications stratégiques

L'utilisation de la blockchain Polygon comme infrastructure C2 et de Session messenger pour les communications représente une évolution majeure dans le paysage des ransomwares. Cette architecture décentralisée rend les efforts de takedown par les autorités considérablement plus complexes : les smart contracts sont immuables et résistants à la censure, le réseau Session est décentralisé et anonyme. Le modèle d'affiliation (Lynx, INC) montre une consolidation du marché RaaS. La concentration des victimes en Europe suggère un ciblage géographique délibéré. Le geofencing linguistique (exclusion CIS/Russie) est un indicateur fort du lieu d'origine probable des opérateurs. L'adoption de Rust pour l'encryptor suit une tendance observée chez plusieurs acteurs de menace récents, offrant des avantages en termes de performance et d'analyse plus complexe pour les chercheurs. Les organisations doivent repenser leurs stratégies de défense pour inclure la surveillance du trafic blockchain et la détection de comportements plutôt que la simple liste noire d'IOCs.

---

### Recommandations

* Activer Controlled Folder Access (CFA) en mode blocage sur les assets sensibles
* Activer tamper protection sur tous les endpoints pour empêcher la désactivation de Defender
* Déployer les règles ASR : blocage exécutables non prevalents, blocage PSExec/WMI, protection avancée ransomware
* Surveiller le trafic sortant vers les endpoints RPC Polygon publics connus
* Maintenir des sauvegardes hors ligne testées régulièrement (3-2-1 rule)
* Former les équipes SOC aux indicateurs comportementaux de DeadLock (throttling, chiffrement partiel, effacement journaux)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer Controlled Folder Access (CFA) en mode audit pour évaluer l'impact, puis basculer en mode blocage
* Activer tamper protection sur Microsoft Defender Antivirus pour empêcher la désactivation des services de sécurité
* Vérifier que les sauvegardes hors ligne (offline) sont opérationnelles et testées régulièrement
* Déployer EDR en mode blocage (block mode) sur tous les endpoints
* Documenter les règles ASR recommandées : blocage exécutables non prevalents, blocage PSExec/WMI, protection avancée anti-ransomware

#### Phase 2 — Détection et analyse

* Surveiller la création de fichiers .cmd aléatoires (8 caractères majuscules) dans ProgramData ou Temp avec exécution via ShellExecuteW RunAs
* Détecter l'activation en masse de privilèges token (SeDebugPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege) sur un même processus
* Surveiller la modification de clés registre HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels (Enabled=0, SDDL restrictif)
* Détecter la création de la clé HKLM\SOFTWARE\Classes\.dlock\DefaultIcon
* Surveiller les requêtes HTTP vers des endpoints RPC Polygon (polygon-bor-rpc.publicnode[.]com, polygon-rpc[.]com, etc.)
* Alerte sur changement de wallpaper système via HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Wallpaper
* Détecter la terminaison en masse de processus (msmpeng, explorer, taskmgr, onedrive, etc.) et la désactivation de services (windefend, vss, wbengine)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les machines compromises du réseau pour empêcher la propagation latérale
* Bloquer les domaines de leak site au niveau DNS/pare-feu : deadlock.liveblog365[.]com, dlock.liveblog365[.]com, deadlockblog.great-site[.]net, deadlockblog.medianewsonline[.]com
* Bloquer les endpoints RPC Polygon utilisés par le recovery chat HTML au niveau du proxy de sortie
* Restaurer les services de sécurité désactivés (windefend, vss, wbengine) depuis une image de référence saine
* Préserver les artefacts forensiques (mémoire, disque) avant réinstallation pour analyse post-incident
* Vérifier l'intégrité des sauvegardes hors ligne et restaurer depuis des copies non connectées

#### Phase 4 — Activités post-incident

* Analyser les journaux résiduels (SIEM, EDR, pare-feu) pour reconstituer la chaîne d'attaque et identifier le vecteur initial
* Vérifier l'absence de persistance résiduelle (raccourcis Startup, tâches planifiées, services modifiés)
* Réinitialiser tous les credentials potentiellement compromis (AD, comptes locaux, services cloud)
* Mener une revue de la configuration Firestore/Firebase si des services cloud sont utilisés
* Documenter le timeline d'attaque et mettre à jour les playbooks IR avec les IOCs DeadLock
* Évaluer l'exposition des données exfiltrées via le blog de leak DeadLock (smart contracts Polygon)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des fichiers avec extension .dlock sur tous les endpoints et serveurs de fichiers
* Chercher des processus effectuant des requêtes eth_call vers des smart contracts Polygon (fonction selector 0x933a9ce8, 0xd4070542)
* Détecter des connexions vers des nodes Session messenger depuis des navigateurs ou applications non standard
* Rechercher des fichiers HTML nommés RECOVERY_CHAT.*.html sur les racines de disques et dossiers Desktop
* Scanner les fichiers .cmd dans ProgramData avec noms aléatoires de 8 caractères majuscules
* Surveiller le trafic vers les 6 endpoints RPC Polygon publics utilisés par le recovery chat
* Rechercher des modifications de clé registre WINEVT\Channels avec SDDL restrictif

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| HASH_SHA256 | `a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4` | High |
| URL | `hxxps://deadlock.liveblog365[.]com` | High |
| URL | `hxxps://dlock.liveblog365[.]com` | High |
| URL | `hxxp://deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd[.]onion` | High |
| URL | `hxxps://deadlockblog.great-site[.]net` | High |
| URL | `hxxps://deadlockblog.medianewsonline[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact – chiffrement XChaCha20 + Curve25519 |
| **T1490** | Inhibit System Recovery – suppression VSS, services de sauvegarde désactivés |
| **T1070** | Indicator Removal – effacement des journaux d'événements Windows |
| **T1562** | Impair Defenses – terminaison Windows Defender, SmartScreen, outils de sécurité |
| **T1485** | Data Destruction – vidage corbeille, chiffrement destructif |
| **T1548** | Abuse Elevation Control Mechanism – élévation UAC via batch script |
| **T1136** | Create Account – enregistrement icône .dlock dans le registre |
| **T1027** | Obfuscated Files or Information – configuration XOR 8-byte key |
| **T1071** | Application Layer Protocol – communications via Polygon RPC et Session messenger |

---

### Sources

* [https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)


---

<div id="aeternum-analyse-dun-botnet-loader-utilisant-la-blockchain-polygon-comme-infrastructure-c2-decentralisee"></div>

## Aeternum : analyse d'un botnet loader utilisant la blockchain Polygon comme infrastructure C2 décentralisée

### Résumé

Palo Alto Unit42 publie une analyse détaillée d'Aeternum, un botnet loader C++ qui déplace entièrement son infrastructure C2 vers la blockchain publique Polygon. Au lieu de serveurs centralisés, les commandes chiffrées et en clair sont écrites directement dans des smart contracts. Les machines infectées interrogent en continu des endpoints RPC publics pour récupérer et exécuter ces commandes on-chain. L'analyse couvre trois échantillons : (1) le loader Aeternum qui utilise XOR pour l'obfuscation, des smart contracts Polygon (22 adresses identifiées) avec le function selector 0xb68d1809 (getDomain), un chiffrement faible PBKDF2HMAC/AES-GCM (self-salting password), et exfiltre des données via Telegram API avec des credentials hard-coded ; (2) un échantillon combinant XWorm RAT v7.4, XMRig miner (config via Pastebin) et exfiltration de données vers 193.221.200[.]219 en AES-128-ECB ; (3) un script Python source qui cible 55+ extensions crypto et 10 wallets desktop, utilise Early Bird APC injection via dpapimig.exe, et inclut des checks anti-VM (8GB RAM minimum, Zone.Identifier ADS validation). L'opérateur principal utilise le moniker LenAI avec l'adresse 0xcaf2c54e400437da717cf215181b170f65187abf. Plus de 29 000 événements de détection enregistrés par Palo Alto au 4 juin 2026.

---

### Analyse opérationnelle

Aeternum pose des défis opérationnels majeurs : (1) Le C2 sur blockchain rend les takedowns traditionnels inefficaces car les smart contracts sont immuables ; (2) L'utilisation de 22 adresses de smart contracts différentes complique le blocage par liste noire ; (3) Le chiffrement PBKDF2HMAC avec self-salting est cryptographiquement faible (NIST SP 800-132) et permet le décryptage des commandes avec seulement l'adresse du contrat et le payload ; (4) L'exfiltration via Telegram API avec credentials hard-coded offre un point de blocage (révocation des tokens bot) ; (5) L'utilisation de GitHub pour héberger des payloads malveillants (DotNetZip.dll dans des repos légitimes) élargit la surface d'attaque ; (6) Le multi-stage chaining (loader → XWorm + XMRig + exfiltration) nécessite une détection à chaque étape ; (7) Les checks anti-VM (8GB RAM, Zone.Identifier ADS, noms d'utilisateurs/machines blocklistés) compliquent l'analyse en sandbox. Les équipes SOC doivent surveiller le function selector 0xb68d1809 dans le trafic HTTP sortant, les connexions vers api.telegram[.]org depuis des processus non standard, et les raccourcis .lnk dans le dossier Startup.

---

### Implications stratégiques

La migration du C2 vers la blockchain Polygon représente une tendance émergente et stratégique dans le paysage des menaces. Les acteurs de menace exploitent l'immuabilité et la décentralisation des blockchains publiques pour créer des infrastructures de communication résilientes aux takedowns law enforcement. Cette approche réduit considérablement les coûts d'infrastructure (pas de serveurs à louer, pas de domaines à enregistrer) tout en augmentant la résilience opérationnelle. L'opérateur LenAI affine itérativement le codebase des smart contracts (évolution solc 0.8.0 → 0.8.30), indiquant un développement professionnel et continu. Le ciblage massif des wallets crypto (55+ extensions, 10 desktop wallets) s'inscrit dans la tendance croissante des vols de cryptocurrencies. L'utilisation de GitHub comme canal de distribution de payloads souligne le risque de compromission de la chaîne d'approvisionnement logicielle. Les organisations doivent adapter leurs stratégies de défense pour inclure la surveillance du trafic blockchain et la collaboration avec les plateformes crypto pour le blocage des wallets.

---

### Recommandations

* Surveiller le trafic HTTP sortant pour le function selector 0xb68d1809 (getDomain) caractéristique d'Aeternum
* Bloquer les domaines C2 connus au niveau DNS : update.constant-path[.]xyz, update-launcher[.]xyz, test-steve[.]cyou, cdnjsdelivr[.]beer
* Surveiller les connexions vers api.telegram[.]org depuis des processus non standard (DLL, exécutables C++)
* Déployer des détections pour l'injection Early Bird APC dans dpapimig.exe
* Vérifier les repositories GitHub internes pour la présence de fichiers malveillants (DotNetZip.dll)
* Sensibiliser les utilisateurs aux faux installateurs DBeaver utilisés comme leurre d'ingénierie sociale
* Collaborer avec les plateformes d'échange crypto pour tracer le wallet Monero 82pNS8tBnvZ5cmV1iU9cXdQmhGz95P18fZpASBrxtaSF1ToTmZtf3HGHrdXMt1Znuu8BLU17koPs2hTXxTajdTviLcgbbAi

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier et surveiller les endpoints RPC Polygon publics dans les règles de sortie du pare-feu
* Déployer des règles de détection pour le function selector 0xb68d1809 (getDomain) dans le trafic HTTP sortant
* Maintenir une liste de surveillance des smart contracts Polygon associés à Aeternum
* Configurer le filtrage DNS pour bloquer les domaines C2 connus (update.constant-path[.]xyz, update-launcher[.]xyz, test-steve[.]cyou, cdnjsdelivr[.]beer)
* Surveiller les connexions vers api.telegram[.]org depuis des processus non standard (DLL, scripts Python)
* Former les équipes à reconnaître les techniques d'injection Early Bird APC

#### Phase 2 — Détection et analyse

* Détecter les requêtes JSON-RPC HTTP POST vers des endpoints Polygon avec le champ 'data' contenant 0xb68d1809
* Surveiller la création de raccourcis .lnk dans le dossier Startup avec des noms comme Wmi_Framework_APIKEY_wmsnet_*.lnk ou PythonLauncher-*.lnk
* Détecter l'injection Early Bird APC dans dpapimig.exe (processus signé légitime détourné)
* Surveiller les téléchargements de DotNetZip.dll depuis des repositories GitHub suspects
* Détecter les connexions à api.telegram[.]org avec User-Agent 'SystemInfo Bot/2.0' ou 'cpp-httplib/0.18.3'
* Alerte sur les connexions à 193.221.200[.]219 avec exfiltration de données Base64
* Surveiller la création de fichiers esewurmgvbqt.exe ou XWormclient.exe dans le dossier Temp

#### Phase 3 — Confinement, éradication et récupération

* Isoler les machines compromises du réseau pour empêcher la communication C2 blockchain
* Bloquer les domaines C2 et IP d'exfiltration au niveau DNS et pare-feu (193.221.200[.]219, sekirolegion.duckdns[.]org)
* Révoquer les tokens Telegram bot compromis (8305917772:AAHAou..., 7356125890:AAF5ncBIc2pJrEfYPAmy2g9YS7B5NjmtwTc)
* Supprimer les raccourcis de persistance dans le dossier Startup
* Terminer les processus de minage XMRig et les processus injectés (dpapimig.exe détourné)
* Bloquer les wallets Monero identifiés au niveau des plateformes d'échange si applicable

#### Phase 4 — Activités post-incident

* Analyser les smart contracts Polygon associés pour identifier les commandes C2 historiques et les domaines rotés
* Vérifier l'absence de persistance résiduelle (raccourcis Startup, copies dans AppData\Local)
* Réinitialiser tous les credentials stockés sur les machines compromises (notamment wallets crypto, mots de passe navigateur)
* Évaluer l'étendue de l'exfiltration de données via Telegram (captures d'écran, infos système)
* Documenter la chaîne d'attaque complète et mettre à jour les playbooks IR avec les IOCs Aeternum
* Vérifier si des extensions de navigateur crypto (55+) ou wallets desktop (10) ont été compromis

#### Phase 5 — Threat Hunting (proactif)

* Rechercher le function selector 0xb68d1809 dans les logs de trafic HTTP sortant (proxy, NGFW)
* Scanner les endpoints pour la présence de fichiers Build.exe, XBinderOutput_protected.exe, DotNetZip.dll
* Chercher des processus effectuant des requêtes vers des endpoints RPC Polygon publics multiples
* Rechercher des raccourcis .lnk dans les dossiers Startup avec des noms contenant 'Wmi_Framework' ou 'PythonLauncher'
* Surveiller les connexions Telegram API depuis des processus non navigateurs (DLL, exécutables C++)
* Détecter les processus dpapimig.exe avec des comportements anormaux (connexions réseau, injection mémoire)
* Rechercher des fichiers de configuration XMRig dans le dossier Temp ou AppData
* Scanner les repositories GitHub internes pour des fichiers malveillants hébergés (DotNetZip.dll)

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| HASH_SHA256 | `5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898` | High |
| HASH_SHA256 | `f2a326cff405299e4ebdfaac955c52fc7e496544eaa0921ecad4816cb3ae3a27` | High |
| HASH_SHA256 | `ea1b6ff3a0c1a749b9f09d66789973321d63d8896b48f7345193bdad512950a2` | High |
| HASH_SHA256 | `1505eda3da68e2ff9919b55a31018bd30a991236f041aee835f3bc4e430ce505` | High |
| HASH_SHA256 | `4e24bbd0fabac6c3efcec943046afbfd332b2c0108a13becfda23a0e26f9ff5f` | High |
| HASH_SHA256 | `81bb80d9c5a97dc41b65f6248c131963c91346eb4fb672836b3d53ae67564d9f` | High |
| IP | `193.221.200[.]219` | High |
| DOMAIN | `gulf.moneroocean[.]stream` | High |
| DOMAIN | `sekirolegion.duckdns[.]org` | High |
| DOMAIN | `download.sftp-api-group-wechat[.]com` | High |
| DOMAIN | `update.constant-path[.]xyz` | High |
| DOMAIN | `update-launcher[.]xyz` | High |
| DOMAIN | `test-steve[.]cyou` | High |
| DOMAIN | `cdnjsdelivr[.]beer` | Medium |
| URL | `hxxp://sekirolegion.duckdns[.]org/api/endpoint.php` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1071** | Application Layer Protocol – C2 via Polygon RPC endpoints et Telegram API |
| **T1105** | Ingress Tool Transfer – téléchargement de payloads depuis GitHub |
| **T1059** | Command and Scripting Interpreter – Python script pour multi-stage decryption |
| **T1547** | Boot or Logon Autostart Execution – raccourci Startup folder pour persistance |
| **T1055** | Process Injection – Early Bird APC injection via dpapimig.exe |
| **T1027** | Obfuscated Files or Information – XOR obfuscation, ChaCha20/AES multi-layer |
| **T1496** | Resource Hijacking – XMRig cryptocurrency miner |
| **T1567** | Exfiltration Over Web Service – exfiltration via Telegram API |
| **T1552** | Unsecured Credentials – credentials Telegram bot hard-coded dans le binaire |
| **T1083** | File and Directory Discovery – collecte infos système (CPU, RAM, GPU, UAC) |
| **T1218** | System Binary Proxy Execution – utilisation de putty.exe légitime pour staging |

---

### Sources

* [https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/](https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/)
* [https://otx.alienvault.com/pulse/6a7a570d454dd1ca4a1449b2](https://otx.alienvault.com/pulse/6a7a570d454dd1ca4a1449b2)
* [https://social.raytec.co/@techbot/117073705664484048](https://social.raytec.co/@techbot/117073705664484048)


---

<div id="tldv-181-874-reunions-exposees-par-defaut-disolation-tenant-sur-firestore"></div>

## tl;dv : 181 874 réunions exposées par défaut d'isolation tenant sur Firestore

### Résumé

Un chercheur en sécurité révèle qu'une plateforme d'enregistrement de réunions IA, tl;dv (Too Long; Didn't View), laisse sa base de données Firestore (projects/lmi-store) entièrement ouverte à l'énumération cross-tenant. Tout utilisateur authentifié de tl;dv peut interroger la collection meetings et accéder aux métadonnées de toutes les réunions de tous les comptes : email du créateur, conference ID (joignable Google Meet/Teams), provider, statut d'enregistrement. 181 874 enregistrements de réunions appartenant à 84 312 utilisateurs uniques sur 35 003 domaines sont exposés, dont des réunions gouvernementales de 23 pays (Brésil, Ukraine, Malaisie, etc.), des universités (Berkeley, University of Tokyo) et des entreprises (HubSpot, Mitsui). Environ 1 000 meetings en statut 'recording' exposent des conference IDs actifs permettant de rejoindre des appels en direct. Le chercheur a rejoint deux réunions en proof-of-concept. L'application interne worldcup.tldv.io expose également l'annuaire employé sans authentification. La vulnérabilité a été signalée le 28 janvier 2026 et reste non corrigée en juillet 2026 malgré de multiples relances.

---

### Analyse opérationnelle

Cette exposition de données pose des risques opérationnels directs : (1) Les conference IDs exposés permettent à un attaquant de rejoindre des réunions en cours (Google Meet, Teams) sans invitation, exposant des discussions sensibles en temps réel ; (2) Les métadonnées de réunions (emails, horaires, participants) constituent une source d'OSINT pour du spear-phishing ciblé ; (3) L'absence d'isolation tenant sur Firestore est une erreur de configuration corrigée sur toutes les autres collections (users, chats, transcripts, recordings retournent 403) mais oubliée sur meetings ; (4) L'application worldcup.tldv.io expose 19 emails d'employés @tldv[.]io sans authentification, facilitant le targeting ; (5) Le délai de 6 mois sans correction malgré disclosure crée une fenêtre d'exploitation prolongée. Les équipes SOC utilisant tl;dv doivent vérifier si leurs meetings sont exposés, surveiller les accès non autorisés aux conférences, et envisager une migration vers une plateforme alternative sécurisée.

---

### Implications stratégiques

Cette breach illustre plusieurs enjeux stratégiques : (1) Les plateformes SaaS d'enregistrement de réunions constituent une surface d'attaque critique souvent négligée par les organisations qui adoptent ces outils sans audit de sécurité ; (2) L'exposition de réunions gouvernementales de 23 pays soulève des questions de sécurité nationale et de souveraineté des données ; (3) Le non-respect du SLA de réponse de 24h annoncé par tl;dv (SOC2, GDPR compliant) démontre l'écart entre les certifications de conformité et la posture de sécurité réelle ; (4) L'absence de bug bounty program et l'ignorance prolongée de la disclosure créent un précédent dangereux pour la confiance dans les plateformes EU ; (5) Les organisations doivent intégrer l'audit de configuration cloud (Firebase, Firestore security rules) dans leur programme de due diligence vendor. Cette breach pourrait déclencher des actions réglementaires GDPR étant donné l'hébergement EU et le volume de données personnelles exposées.

---

### Recommandations

* Si votre organisation utilise tl;dv : auditer immédiatement les meetings exposés et évaluer l'impact
* Vérifier que les conference IDs Google Meet/Teams n'ont pas été utilisés pour des accès non autorisés
* Envisager une migration vers une plateforme alternative avec isolation tenant vérifiée
* Intégrer l'audit de configuration Firebase/Firestore security rules dans les due diligence vendor
* Sensibiliser les utilisateurs aux risques d'enregistrement de réunions sur des plateformes tierces
* Surveiller les accès non autorisés aux conférences via les logs Google Workspace / Microsoft Teams

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Auditer toutes les collections Firestore pour vérifier la présence de règles de sécurité (security rules) par collection
* Vérifier l'isolation tenant sur toutes les collections contenant des données multi-utilisateurs
* Mettre en place un processus de réponse aux disclosures de sécurité avec SLA de 24h
* Surveiller les requêtes anormales sur les collections Firestore (volume, fréquence, cross-tenant)
* Implémenter une authentification et une autorisation sur toutes les API internes

#### Phase 2 — Détection et analyse

* Surveiller les requêtes Firestore provenant de tokens Firebase valides mais accédant à des meetings d'autres tenants
* Détecter les patterns d'énumération : requêtes massives sur la collection meetings avec pagination
* Alerte sur les accès à worldcup.tldv.io/api/entities/Player sans session cookie
* Surveiller les requêtes vers gw.tldv.io/v1/users/firebase/token depuis des comptes free-tier avec volume anormal
* Détecter les jointures de conference IDs Google Meet/Teams depuis des comptes non invités

#### Phase 3 — Confinement, éradication et récupération

* Appliquer immédiatement les Firestore security rules sur la collection meetings (403 pour accès cross-tenant)
* Révoquer les tokens Firebase potentiellement abusés
* Sécuriser ou désactiver l'application worldcup.tldv.io (API Player sans auth)
* Notifier les utilisateurs dont les meetings ont été exposés (181 874 enregistrements, 84 312 utilisateurs)
* Bloquer les adresses IP ayant effectué des requêtes d'énumération massives
* Vérifier si des conference IDs ont été utilisés pour rejoindre des appels en cours

#### Phase 4 — Activités post-incident

* Évaluer l'étendue de l'exposition : 181 874 meetings, 84 312 utilisateurs, 35 003 domaines, 23 gouvernements
* Identifier et notifier les organisations gouvernementales impactées (Brésil, Ukraine, Malaisie, etc.)
* Auditer toutes les autres collections Firestore pour des vulnérabilités similaires d'isolation tenant
* Mettre en place un programme de bug bounty pour les futurs disclosures
* Documenter la timeline de disclosure (28 janvier 2026 → juillet 2026, toujours non corrigé)
* Évaluer les obligations réglementaires (GDPR, notification de breach) pour les données EU exposées

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs Firebase les requêtes d'énumération sur la collection meetings par des comptes free-tier
* Identifier les conference IDs Google Meet/Teams qui ont été rejoints par des participants non invités
* Analyser les logs d'accès à worldcup.tldv.io pour identifier les requêtes non authentifiées sur /api/entities/Player
* Corréler les tokens Firebase émis avec les patterns d'accès anormaux (volume, cross-tenant)
* Vérifier si les 1 000+ meetings publics ont été accédés et par qui
* Surveiller les sous-domaines tldv.io (cappellini, carbonara, fusilli, etc.) pour des vulnérabilités similaires

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `tldv[.]io` | High |
| DOMAIN | `gw.tldv[.]io` | High |
| DOMAIN | `worldcup.tldv[.]io` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552** | Unsecured Credentials – absence d'authentification sur l'API Player (worldcup.tldv.io) |
| **T1213** | Data from Information Repositories – énumération de la collection meetings Firestore sans isolation tenant |
| **T1087** | Account Discovery – exposition de 84 312 utilisateurs uniques et 19 emails d'employés |
| **T1530** | Data from Cloud Storage Object – accès non autorisé aux enregistrements de réunions via Firebase token |

---

### Sources

* [https://bobdahacker.com/blog/tldv-hack](https://bobdahacker.com/blog/tldv-hack)
* [https://s.ovalerio.net/@dethos/117073696836772617](https://s.ovalerio.net/@dethos/117073696836772617)


---

<div id="malware-4-noobs-partie-i-introduction-aux-concepts-de-developpement-malware-stagers-et-lolbins"></div>

## Malware 4 Noobs (Partie I) : introduction aux concepts de développement malware, stagers et LOLBINs

### Résumé

vx-underground publie la première partie d'un guide éducatif sur le développement de malware Windows. L'article distingue les auteurs de malware malveillants (Financially Motivated Threat Actors vs State-Sponsored/APT) des chercheurs et éducateurs. Il explique les différences de TTPs entre les deux catégories : les acteurs financiers privilégient le smash-and-grab, le MaaS (Malware-as-a-Service) et le volume d'infection, tandis que les APT ciblent l'espionnage avec persistance. L'article détaille le concept de staging (stagers, initial access files, chaining), l'environmental keying (détection VM, géolocalisation, produits de sécurité), le masquerading de binaires (double extension, faux mods de jeux, fausses invitations Zoom), l'abus de LOLBINs (Living off the Land Binaries) pour le malware fileless, et la technique ClickFix (Mr.d0x) qui combine masquerading, LOLBIN et clipboard pour l'exécution par l'utilisateur.

---

### Analyse opérationnelle

Ce guide éducatif a une valeur opérationnelle pour les équipes SOC : (1) Il fournit une taxonomie claire des types d'acteurs de menace et leurs motivations, aidant à prioriser les alertes ; (2) La description du staging et de l'environmental keying permet de mieux comprendre pourquoi certains malwares ne se déclenchent pas en sandbox et d'adapter les environnements d'analyse ; (3) L'explication des LOLBINs et du concept fileless malware guide la création de règles de détection comportementale plutôt que signature-based ; (4) La technique ClickFix est particulièrement pertinente car elle exploite l'utilisateur final (clipboard → Win+R → exécution) et nécessite une détection au niveau du clipboard et de l'exécution de commandes ; (5) La liste des MaaS courants (StealC, Rhadamanthys, RedLine, Vidar, etc.) doit être intégrée dans les watchlists SOC.

---

### Implications stratégiques

La publication de guides éducatifs sur le développement malware par des acteurs de la communauté underground souligne la démocratisation des connaissances en matière de malware. Cette tendance abaisse le barrier to entry pour les nouveaux acteurs de menace et augmente le volume global de menaces. La distinction entre APT et financially motivated actors reste pertinente pour la priorisation stratégique de défense : les organisations gouvernementales et de défense doivent se concentrer sur les APT (espionnage, persistance), tandis que les entreprises doivent prioriser les menaces financières (MaaS, stealers, ransomware). L'évolution vers le fileless malware et l'abus de LOLBINs nécessite un changement de paradigme : passer de la détection par signature à la détection comportementale et l'analyse heuristique.

---

### Recommandations

* Intégrer la liste des MaaS courants (StealC, Rhadamanthys, RedLine, Vidar, etc.) dans les watchlists SOC
* Déployer des détections pour la technique ClickFix (surveillance clipboard + exécution Win+R)
* Maintenir une liste à jour des LOLBINs (LOLBAS project) pour la création de règles de détection
* Adapter les environnements de sandbox pour contrer l'environmental keying (VM detection bypass)
* Former les équipes SOC aux concepts de staging, chaining et masquerading

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Former les équipes SOC aux concepts de staging, environmental keying et LOLBINs
* Maintenir une liste à jour des LOLBINs connus (LOLBAS project) pour la détection
* Déployer des règles de détection pour les techniques ClickFix (clipboard → Win+R → exécution)
* Surveiller les types de fichiers couramment utilisés comme stagers (.ps1, .bat, .vbs, .js, .hta, .lnk)

#### Phase 2 — Détection et analyse

* Détecter les tentatives d'environmental keying (vérifications VM, géolocalisation IP, produits de sécurité installés)
* Surveiller l'exécution de LOLBINs avec des paramètres anormaux (téléchargement, exécution de code)
* Détecter les fichiers avec double extension (.mp3.exe, .doc.exe) dans les téléchargements et emails
* Alerte sur la copie automatique de contenu dans le clipboard depuis des pages web (technique ClickFix)

#### Phase 3 — Confinement, éradication et récupération

* Isoler les machines ayant exécuté des stagers suspects
* Bloquer les domaines de distribution de stagers (faux sites de mods, faux invitations Zoom)
* Analyser les stagers pour identifier les payloads secondaires et les C2 associés

#### Phase 4 — Activités post-incident

* Documenter la chaîne d'infection complète (stager → payload → C2)
* Mettre à jour les règles de détection avec les IOCs extraits de chaque étape
* Évaluer l'impact du payload final (exfiltration, persistance, chiffrement)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des stagers dans les dossiers de téléchargements et emails (.ps1, .bat, .lnk non standard)
* Surveiller l'exécution de LOLBINs avec des arguments de téléchargement ou d'exécution de code
* Détecter les patterns ClickFix : contenu clipboard contenant des commandes PowerShell/cmd
* Analyser les fichiers récemment téléchargés pour du masquerading (double extension, icônes trompeuses)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1027** | Obfuscated Files or Information – stagers pour environmental keying et evasion |
| **T1218** | System Binary Proxy Execution – abus de LOLBINs pré-installés Windows |
| **T1059** | Command and Scripting Interpreter – stagers PowerShell, batch, VBS, JS |
| **T1036** | Masquerading – masquerading de binaires (double extension, faux mods de jeux) |
| **T1204** | User Execution – technique ClickFix (copie clipboard → Win+R → exécution) |

---

### Sources

* [https://malwaresourcecode.com/home/my-projects/write-ups/part-i-malware-4-noobs-version-0](https://malwaresourcecode.com/home/my-projects/write-ups/part-i-malware-4-noobs-version-0)
* [https://infosec.exchange/@AmmarSpaces/117073729706461650](https://infosec.exchange/@AmmarSpaces/117073729706461650)


---

<div id="noisehound-scoring-des-chemins-dattaque-bloodhound-avec-prise-en-compte-de-la-detectabilite"></div>

## NoiseHound : scoring des chemins d'attaque BloodHound avec prise en compte de la détectabilité

### Résumé

NoiseHound est un outil open-source (Python, licence MIT) qui ajoute une dimension de détectabilité au scoring des chemins d'attaque générés par BloodHound. L'outil évalue les chemins d'attaque Active Directory en tenant compte de la probabilité de détection par les solutions de sécurité déployées, permettant aux équipes red team et SOC de prioriser les chemins les plus furtifs.

---

### Analyse opérationnelle

NoiseHound comble un gap opérationnel entre les équipes red team et blue team : en scorant les chemins d'attaque BloodHound selon leur détectabilité, il permet aux équipes SOC d'identifier les chemins aveugles (faible détectabilité) qui nécessitent une couverture de détection renforcée. Les équipes red team peuvent l'utiliser pour sélectionner les chemins les plus furtifs lors d'exercices d'attaque simulée. L'outil aide à prioriser les remédiations de configuration Active Directory en se concentrant sur les chemins à la fois exploitables et difficiles à détecter.

---

### Implications stratégiques

L'intégration de la dimension de détectabilité dans l'analyse des chemins d'attaque Active Directory représente une évolution vers une approche plus pragmatique de la sécurisation AD. Plutôt que de tenter de fermer tous les chemins d'attaque (souvent irréaliste dans des environnements AD complexes), les organisations peuvent prioriser les chemins à la fois critiques et furtifs. Cette approche aligne les exercices red team avec les capacités de détection réelles du SOC, créant un feedback loop plus efficace entre attaque et défense.

---

### Recommandations

* Évaluer NoiseHound dans le cadre du programme de sécurité offensive et défensive
* Intégrer le scoring de détectabilité dans le processus de priorisation des remédiations AD
* Utiliser NoiseHound pour identifier les gaps de couverture de détection sur les chemins d'attaque critiques

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Évaluer NoiseHound pour le scoring des chemins d'attaque BloodHound avec prise en compte de la détectabilité
* Maintenir des graphes BloodHound à jour pour l'environnement Active Directory
* Identifier les chemins d'attaque à haut risque et prioriser leur remédiation

#### Phase 2 — Détection et analyse

* Surveiller les requêtes LDAP anormales correspondant aux patterns d'énumération BloodHound
* Corréler les chemins d'attaque identifiés par NoiseHound avec les alertes de sécurité existantes
* Identifier les chemins d'attaque à faible détectabilité signalés par NoiseHound pour prioriser le durcissement

#### Phase 3 — Confinement, éradication et récupération

* Bloquer ou restreindre les comptes et chemins identifiés comme critiques par NoiseHound
* Appliquer des corrections de configuration AD pour briser les chemins d'attaque à haut risque

#### Phase 4 — Activités post-incident

* Utiliser NoiseHound pour vérifier que les chemins d'attaque exploités lors d'un incident ont été fermés
* Mettre à jour les graphes BloodHound post-remédiation et re-scanner avec NoiseHound

#### Phase 5 — Threat Hunting (proactif)

* Utiliser NoiseHound pour identifier les chemins d'attaque à faible détectabilité nécessitant une surveillance renforcée
* Rechercher des indicateurs d'énumération Active Directory correspondant aux patterns BloodHound/NoiseHound
* Prioriser la chasse aux menaces sur les chemins d'attaque avec le score de détectabilité le plus faible

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1087** | Account Discovery – énumération et scoring des chemins d'attaque AD |
| **T1068** | Exploitation for Privilege Escalation – identification des chemins d'escalade via BloodHound |
| **T1021** | Remote Services – chemins de mouvement latéral identifiés par BloodHound |

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1vl0t2u/noisehound_detectionaware_bloodhound_attackpath/](https://www.reddit.com/r/redteamsec/comments/1vl0t2u/noisehound_detectionaware_bloodhound_attackpath/)


---

<div id="operateur-russophone-chainage-de-cve-sur-cameras-et-routeurs-pour-creer-un-pipeline-proxy-et-de-visualisation-contre-lukraine"></div>

## Opérateur russophone : chaînage de CVE sur caméras et routeurs pour créer un pipeline proxy et de visualisation contre l'Ukraine

### Résumé

Un article publié sur r/redteamsec décrit comment un opérateur russophone a chaîné des vulnérabilités (CVE) sur des caméras IP et des routeurs pour construire un pipeline de proxy et de visualisation utilisé contre l'Ukraine. L'opérateur a exploité des dispositifs IoT exposés sur Internet pour créer une infrastructure de relais et de surveillance, transformant des équipements compromis en outils de collecte et de transmission de données.

---

### Analyse opérationnelle

Ce cas illustre l'exploitation systématique de dispositifs IoT vulnérables (caméras IP, routeurs) comme infrastructure d'attaque. Pour les équipes SOC : (1) Les dispositifs IoT exposés sur Internet constituent une surface d'attaque souvent négligée mais activement exploitée par les acteurs de menace ; (2) Le chaînage de CVE sur des dispositifs IoT permet de construire des infrastructures proxy difficiles à attribuer et à démonter ; (3) Les caméras IP compromises peuvent servir de points de visualisation pour la surveillance tactique ; (4) La détection nécessite une surveillance du trafic anormal sur les segments IoT (connexions sortantes inattendues, patterns de proxy) ; (5) La remédiation passe par la mise à jour des firmwares, la segmentation réseau des dispositifs IoT, et la réduction de l'exposition Internet.

---

### Implications stratégiques

L'exploitation d'IoT pour des opérations de renseignement et de proxy s'inscrit dans le contexte du conflit russo-ukrainien où les infrastructures civiles sont ciblées. Les dispositifs IoT (caméras, routeurs) représentent une ressource stratégique pour les acteurs étatiques et non-étatiques : ils sont nombreux, souvent mal sécurisés, exposés sur Internet, et difficiles à attribuer. La construction de pipelines de proxy à partir d'IoT compromis permet de masquer l'origine des attaques et de créer des canaux de surveillance persistants. Les organisations gouvernementales et de défense doivent intégrer l'audit IoT dans leur programme de sécurité, en particulier dans les zones de conflit. La régulation de la sécurité des dispositifs IoT (cyber-resilience act, baseline security requirements) devient un enjeu géopolitique.

---

### Recommandations

* Inventorier et segmenter tous les dispositifs IoT (caméras, routeurs) sur un réseau dédié
* Maintenir une veille CVE sur les dispositifs IoT déployés et appliquer les correctifs rapidement
* Surveiller le trafic sortant des segments IoT pour détecter les patterns de proxy ou de surveillance
* Réduire l'exposition Internet des dispositifs IoT au strict nécessaire
* Appliquer des configurations de durcissement sur les caméras IP et routeurs (mots de passe forts, désactivation services inutiles)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les dispositifs IoT exposés (caméras, routeurs) et leur version firmware
* Maintenir une veille CVE sur les dispositifs IoT déployés (caméras IP, routeurs边缘)
* Segmenter les dispositifs IoT sur un réseau dédié avec accès restreint

#### Phase 2 — Détection et analyse

* Surveiller le trafic anormal depuis des caméras IP ou routeurs (connexions sortantes, proxy traffic)
* Détecter les tentatives d'exploitation de CVE connues sur les dispositifs IoT exposés
* Surveiller les changements de configuration sur les caméras et routeurs (redirection de ports, proxy)

#### Phase 3 — Confinement, éradication et récupération

* Isoler les dispositifs IoT compromis du réseau
* Mettre à jour les firmwares des dispositifs IoT vulnérables
* Bloquer le trafic proxy sortant depuis les segments IoT

#### Phase 4 — Activités post-incident

* Analyser les logs des dispositifs IoT compromis pour identifier l'étendue de l'exploitation
* Vérifier si les dispositifs ont été utilisés pour des attaques de rebond vers d'autres cibles
* Renforcer la segmentation réseau IoT et appliquer le principe de moindre privilège

#### Phase 5 — Threat Hunting (proactif)

* Scanner les dispositifs IoT exposés pour des CVE connues exploitables
* Rechercher des patterns de trafic proxy sur les segments IoT
* Corréler les indicateurs avec les campagnes russophones ciblant l'Ukraine

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application – exploitation de CVE sur caméras et routeurs exposés |
| **T1090** | Proxy – utilisation des dispositifs compromis comme infrastructure proxy |
| **T1059** | Command and Scripting Interpreter – automatisation de l'exploitation en chaîne |

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1vktd2p/how_one_russianspeaking_operator_chained_camera/](https://www.reddit.com/r/redteamsec/comments/1vktd2p/how_one_russianspeaking_operator_chained_camera/)


---

<div id="pypspipejack-implementation-python-dune-technique-de-mouvement-lateral-et-descalade-de-privileges-via-powershell-named-pipes"></div>

## PyPsPipeJack : implémentation Python d'une technique de mouvement latéral et d'escalade de privilèges via PowerShell named pipes

### Résumé

PyPsPipeJack est une implémentation Python de la technique OpenPsPipeJack, une nouvelle technique de mouvement latéral et d'escalade de privilèges utilisant les named pipes PowerShell. L'outil démontre comment les named pipes Windows peuvent être exploités pour exécuter des commandes à distance et escalader les privilèges sur des machines cibles.

---

### Analyse opérationnelle

PyPsPipeJack expose une technique offensive utilisant les named pipes PowerShell pour le mouvement latéral et l'escalade de privilèges. Pour les équipes SOC : (1) Les named pipes PowerShell sont un canal de communication inter-processus légitime mais rarement surveillé, créant un gap de détection ; (2) La technique permet d'exécuter des commandes à distance sans utiliser les canaux traditionnels (WinRM, PSExec, WMI) qui sont mieux surveillés ; (3) La détection nécessite Sysmon Event ID 17 (Pipe Event Created) et 18 (Pipe Event Connected) avec surveillance des noms de pipes non standard ; (4) Le PowerShell Script Block Logging (Event ID 4104) doit être activé pour capturer les commandes exécutées via named pipes ; (5) La remédiation passe par le Constrained Language Mode PowerShell et la restriction des named pipes accessibles.

---

### Implications stratégiques

La publication d'outils comme PyPsPipeJack démocratise des techniques de mouvement latéral jusque-là réservées à des acteurs avancés. Les named pipes PowerShell représentent une surface d'attaque sous-estimée car ils sont un mécanisme Windows légitime rarement audité. Les organisations doivent intégrer la surveillance des named pipes dans leur stratégie de détection, en particulier pour les environnements où PowerShell est largement utilisé (administration système, automation). Cette technique souligne l'importance de durcir PowerShell (Constrained Language Mode, script block logging, transcription) plutôt que de tenter de le désactiver entièrement, ce qui est souvent irréaliste.

---

### Recommandations

* Activer Sysmon Event ID 17/18 pour surveiller la création et connexion de named pipes
* Activer PowerShell Script Block Logging (Event ID 4104) pour capturer les commandes exécutées via named pipes
* Déployer PowerShell en Constrained Language Mode pour restreindre les capacités d'exécution
* Établir une baseline des named pipes légitimes pour identifier les pipes anormaux
* Intégrer la détection des named pipes suspects dans les règles EDR et SIEM

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Surveiller la création de named pipes PowerShell avec des noms non standard
* Documenter les named pipes légitimes utilisés dans l'environnement pour établir une baseline
* Restreindre l'exécution PowerShell via Constrained Language Mode et script block logging

#### Phase 2 — Détection et analyse

* Détecter la création de named pipes avec des noms aléatoires ou suspects via Sysmon Event ID 17/18
* Surveiller les connexions PowerShell à distance utilisant des named pipes (Event ID 4104, 4103)
* Corréler la création de named pipes avec des tentatives d'escalade de privilèges

#### Phase 3 — Confinement, éradication et récupération

* Isoler les machines où des named pipes suspects ont été détectés
* Terminer les sessions PowerShell utilisant des named pipes non standard
* Bloquer l'exécution de PowerShell non signé ou non approuvé

#### Phase 4 — Activités post-incident

* Analyser les logs Sysmon (Event ID 17/18) pour identifier tous les named pipes créés pendant l'attaque
* Vérifier si la technique a été utilisée pour l'escalade de privilèges ou le mouvement latéral
* Mettre à jour les règles de détection avec les patterns de named pipes identifiés

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des named pipes PowerShell non standard dans les logs Sysmon
* Identifier les machines avec des connexions PowerShell à distance via named pipes
* Corréler les named pipes suspects avec des indicateurs d'escalade de privilèges ou de mouvement latéral

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1021** | Remote Services – mouvement latéral via PowerShell named pipes |
| **T1078** | Valid Accounts – escalade de privilèges via named pipes impersonation |
| **T1059** | Command and Scripting Interpreter – PowerShell pour exécution de commandes à distance |
| **T1570** | Lateral Tool Transfer – utilisation de named pipes pour transférer et exécuter des outils |

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1vkidvs/pypspipejack_python_implementation_of/](https://www.reddit.com/r/redteamsec/comments/1vkidvs/pypspipejack_python_implementation_of/)
