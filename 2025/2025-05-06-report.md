# ⚠️Important Vulnerabilities (CVSS > 7.5)⚠️
* 🐞 Vulnérabilités Multiples dans SeaCMS v13.3
* 🐛 Vulnérabilité Critique d'Injection SQL dans la Librairie PHP ADOdb (CVE-2025-46337)
* 🔐 Vulnérabilités Critiques dans les Panneaux d'Alarme Honeywell MB-Secure (CVE-2025-2605)
* 💥 Vulnérabilités Multiples Activement Exploitées dans Langflow (CVE-2025-3248) et Android/FreeType (CVE-2025-27363), et Commvault (CVE-2025-34028)
* 🔓 Vulnérabilité Critique dans le Plugin WordPress OttoKit (CVE-2025-27007)
* 🔐 Vulnérabilité Critique dans OpenCTI (CVE-2025-24977)
* ⚠️ Vulnérabilités Critiques/Élevées dans IBM Cognos Analytics (CVE-2024-51466, CVE-2024-40695)
* 🖱️ Vulnérabilités Élevées/Critiques dans Google Chrome/Edge (CVE-2025-4096, CVE-2025-4050)
* 🔄 Vulnérabilités Critiques dans Tenda AC9 (CVE-2025-45042) et Output Messenger (CVE-2025-27920)
* 🔑 Vulnérabilités Critiques d'Authentification/PrivEsc dans brcc (CVE-2025-45616) et yaoqishan (CVE-2025-45615), et BuddyBoss (CVE-2025-1909)
* 💾 Vulnérabilités Critiques/Élevées d'Injection SQL dans Kashipara Online Service Management Portal (CVE-2025-45322, CVE-2025-45321)
* 🌐 Vulnérabilités Élevées de Buffer Overflow dans Tenda AC1206 (CVE-2025-4299, CVE-2025-4298)
* 📂 Vulnérabilité Élevée de Téléversement de Fichiers dans le Plugin WordPress External Image Replace (CVE-2025-4279)
* 🖥️ Vulnérabilité Élevée d'Escalade de Privilèges dans Webmin (CVE-2025-2774)
* 칩셋 Vulnérabilités Multiples dans les Chipsets MediaTek
* 🍏 Vulnérabilités Corrigées Potentiellement Critiques/Ver dans Apple AirPlay
* ☁️ Vulnérabilité Élevée dans AWS Amplify Studio (CVE-2025-4318)
* 🚪 Vulnérabilité Élevée dans Digigram PYKO-OUT (CVE-2025-3927)

## Table of Contents
* [THREATS](#threats)
    * [🕷️ UNC3944 (Scattered Spider) et DragonForce ciblant le secteur de la vente au détail au Royaume-Uni et ailleurs](#️-unc3944-scattered-spider-et-dragonforce-ciblant-le-secteur-de-la-vente-au-détail-au-royaume-uni-et-ailleurs)
    * [🌕 Luna Moth (Silent Ransom Group) ciblant les entreprises américaines par hameçonnage de rappel (Callback Phishing)](#-luna-moth-silent-ransom-group-ciblant-les-entreprises-américaines-par-hameçonnage-de-rappel-callback-phishing)
    * [🧛‍♂️ Darcula PhaaS : Plateforme d'Hameçonnage-as-a-Service pour le Vol de Cartes de Crédit](#-darcula-phaas--plateforme-d'hameçonnage-as-a-service-pour-le-vol-de-cartes-de-crédit)
    * [🍼 Nouvelle technique de contournement d'EDR ("Bring Your Own Installer") utilisée dans des attaques par ransomware Babuk](#-nouvelle-technique-de-contournement-dedr-bring-your-own-installer-utilisée-dans-des-attaques-par-ransomware-babuk)
* [VULNERABILITIES](#vulnerabilities)
    * [🐛 Vulnérabilité Critique d'Injection SQL dans la Librairie PHP ADOdb (CVE-2025-46337)](#-vulnérabilité-critique-dinjection-sql-dans-la-librairie-php-adodb-cve-2025-46337)
    * [🔐 Vulnérabilités Critiques dans les Panneaux d'Alarme Honeywell MB-Secure (CVE-2025-2605)](#-vulnérabilités-critiques-dans-les-panneaux-dalarme-honeywell-mb-secure-cve-2025-2605)
    * [💥 Vulnérabilités Multiples Activement Exploitées dans Langflow (CVE-2025-3248), Android/FreeType (CVE-2025-27363), et Commvault (CVE-2025-34028)](#-vulnérabilités-multiples-activement-exploitées-dans-langflow-cve-2025-3248-androidfreetype-cve-2025-27363-et-commvault-cve-2025-34028)
    * [🔓 Vulnérabilité Critique dans le Plugin WordPress OttoKit (CVE-2025-27007)](#-vulnérabilité-critique-dans-le-plugin-wordpress-ottokit-cve-2025-27007)
    * [🔐 Vulnérabilité Critique dans OpenCTI (CVE-2025-24977)](#-vulnérabilité-critique-dans-opencti-cve-2025-24977)
    * [⚠️ Vulnérabilités Critiques/Élevées dans IBM Cognos Analytics (CVE-2024-51466, CVE-2024-40695)](#-vulnérabilités-critiquesélevées-dans-ibm-cognos-analytics-cve-2024-51466-cve-2024-40695)
    * [🐞 Vulnérabilités Multiples dans SeaCMS v13.3](#-vulnérabilités-multiples-dans-seacms-v133)
    * [🖱️ Vulnérabilités Élevées/Critiques dans Google Chrome/Edge (CVE-2025-4096, CVE-2025-4050)](#️-vulnérabilités-élevéescritiques-dans-google-chromeedge-cve-2025-4096-cve-2025-4050)
    * [🔄 Vulnérabilités Critiques dans Tenda AC9 (CVE-2025-45042) et Output Messenger (CVE-2025-27920)](#-vulnérabilités-critiques-dans-tenda-ac9-cve-2025-45042-et-output-messenger-cve-2025-27920)
    * [🔑 Vulnérabilités Critiques d'Authentification/PrivEsc dans brcc (CVE-2025-45616), yaoqishan (CVE-2025-45615) et BuddyBoss (CVE-2025-1909)](#-vulnérabilités-critiques-dauthentificationprivesc-dans-brcc-cve-2025-45616-yaoqishan-cve-2025-45615-et-buddyboss-cve-2025-1909)
    * [💾 Vulnérabilités Critiques/Élevées d'Injection SQL dans Kashipara Online Service Management Portal (CVE-2025-45322, CVE-2025-45321)](#-vulnérabilités-critiquesélevées-dinjection-sql-dans-kashipara-online-service-management-portal-cve-2025-45322-cve-2025-45321)
    * [🌐 Vulnérabilités Élevées de Buffer Overflow dans Tenda AC1206 (CVE-2025-4299, CVE-2025-4298)](#-vulnérabilités-élevées-de-buffer-overflow-dans-tenda-ac1206-cve-2025-4299-cve-2025-4298)
    * [📂 Vulnérabilité Élevée de Téléversement de Fichiers dans le Plugin WordPress External Image Replace (CVE-2025-4279)](#-vulnérabilité-élevée-de-téléversement-de-fichiers-dans-le-plugin-wordpress-external-image-replace-cve-2025-4279)
    * [🖥️ Vulnérabilité Élevée d'Escalade de Privilèges dans Webmin (CVE-2025-2774)](#️-vulnérabilité-élevée-descalade-de-privilèges-dans-webmin-cve-2025-2774)
    * [칩셋 Vulnérabilités Multiples dans les Chipsets MediaTek](#칩셋-vulnérabilités-multiples-dans-les-chipsets-mediatek)
    * [🍏 Vulnérabilités Corrigées Potentiellement Critiques/Ver dans Apple AirPlay](#-vulnérabilités-corrigées-potentiellement-critiquesver-dans-apple-airplay)
    * [☁️ Vulnérabilité Élevée dans AWS Amplify Studio (CVE-2025-4318)](#️-vulnérabilité-élevée-dans-aws-amplify-studio-cve-2025-4318)
    * [🚪 Vulnérabilité Élevée dans Digigram PYKO-OUT (CVE-2025-3927)](#-vulnérabilité-élevée-dans-digigram-pyko-out-cve-2025-3927)

# THREATS

## 🕷️ UNC3944 (Scattered Spider) et DragonForce ciblant le secteur de la vente au détail au Royaume-Uni et ailleurs
Des rapports récents lient les activités d'UNC3944 (alias Scattered Spider) et du groupe de ransomware DragonForce, en particulier dans des attaques contre de grands détaillants britanniques (Marks & Spencer, Co-op, Harrods). Ces acteurs partagent des tactiques, notamment l'utilisation de l'ingénierie sociale pour compromettre les équipes de support informatique (help desk) et obtenir un accès initial. UNC3944 est connu pour ses tactiques persistantes d'ingénierie sociale et ciblant divers secteurs, principalement dans les pays anglophones. DragonForce, qui a évolué d'un groupe hacktiviste à une opération RaaS axée sur le profit, utilise un modèle de multi-extorsion et des payloads basés sur le codebase de Conti. Des actions récentes des forces de l'ordre avaient temporairement réduit l'activité d'UNC3944, mais le groupe s'adapte et continue de cibler de grandes organisations.

* Publication date : 2025/05/06
* 🗺️ Source : https://cloud.google.com/blog/topics/threat-intelligence/unc3944-proactive-hardening-recommendations/, https://www.bleepingcomputer.com/news/security/uk-shares-security-tips-after-major-retail-cyberattacks/, https://securityonline.info/dragonforce-ransomware-cartel-hits-uk-retailers-with-custom-payloads-and-global-extortion-campaign/
* 🧑‍💻 Threat Actor : UNC3944 (Scattered Spider, Lapsus$, The Com), DragonForce (RansomBay)
* 🎯 Threat Target : Organisations de vente au détail (UK, US), Technologie, Télécommunications, Services Financiers, Externalisation des processus métier (BPO), Jeux, Hôtellerie, Médias & Divertissement, Gouvernements (Palau, Honolulu OTS), Entreprises (Coca-Cola Singapore, Ohio State Lottery, Yakult Australia), Cabinets d'avocats, Pratiques médicales. Géographie : Principalement pays anglophones (US, CA, UK, AU), récemment Singapour, Inde, Israël, Arabie Saoudite.
* 🦹 Threat Tactic : Ingénierie Sociale (usurpation d'identité help desk, de l'équipe IT), Hameçonnage (Phishing), Credential Stuffing (sur RDP), Exploitation de Vulnérabilités, Mouvement Latéral, Escalade de Privilèges, Persistance, Exfiltration de Données, Extorsion, RaaS (Ransomware-as-a-Service).
* 🛠️ Threat Tools : Ransomware DragonForce (variant de Conti v3, utilise AES et ChaCha8), Cobalt Strike, mimikatz, SystemBC, PingCastle, ADRecon, ADExplorer, SharpHound, Outils RMM (AnyDesk, Splashtop, Syncro, SuperOps, Zoho Assist, Atera), WinSCP (via SFTP), Rclone (cloud syncing), RansomBay (site de fuite de données).
* ❓ MITRE ATT&CK : Ingénierie Sociale (T1348), Obtention d'Accès Initial (T1598.003 - Spearphishing Link), Mouvement Latéral (TA0008), Escalade de Privilèges (TA0004), Exfiltration (TA0010), Impact (TA0040). Specific techniques mentioned in the article include T1078 (Valid Accounts), T1078.003 (Remote Services), T1059 (Command and Scripting Interpreter), T1047 (Windows Management Instrumentation), T1543.003 (Create or Modify System Process: Windows Service), T1021.001 (Remote Services: RDP), T1021.004 (Remote Services: SSH), T1021.006 (Remote Services: WinRM), T1021.005 (Remote Services: VNC), T1021.002 (Remote Services: SMB/Windows Admin Shares), T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1059.004 (Unix Shell), T1059.005 (Visual Basic), T1059.006 (Python), T1059.007 (JavaScript), T1219 (Remote Access Software), T1105 (Ingress Tool Transfer), T1572 (Protocol Tunneling), T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service), T1567.002 (Exfiltration to Cloud Storage), T1490 (Inhibit System Recovery), T1486 (Data Encrypted for Impact), T1485 (Data Destruction), T1491 (Defacement).
* 🛡️ Security Recommandations : Renforcer les processus de vérification d'identité pour le help desk (vérification sur caméra/en personne, ID, questions défi/réponse non publiques). Désactiver/améliorer la validation des réinitialisations de mot de passe en libre-service. Ne pas utiliser les données publiques pour la vérification. Désactiver temporairement les réinitialisations MFA en libre-service pendant les périodes de menace élevée. Supprimer SMS/appel téléphonique/email comme facteurs d'authentification. Utiliser des applications d'authentification résistantes au hameçonnage (correspondance de numéros, géovérification). Transition vers l'authentification sans mot de passe (passwordless). Utiliser des clés de sécurité FIDO2 pour les comptes privilégiés. Empêcher les admins d'enregistrer/utiliser les méthodes MFA héritées. Appliquer des critères multi-contextes pour l'authentification (appareil, emplacement). Restreindre l'enregistrement MFA aux emplacements de confiance et à la conformité des appareils. Investiguer/alerter sur le même MFA/numéro de téléphone enregistré sur plusieurs comptes. Revoir les emplacements IP qui peuvent contourner la MFA. Découpler l'annuaire d'identité (AD) des plateformes d'infrastructure/services cloud pour l'accès privilégié. Créer des comptes admin locaux avec des mots de passe complexes et MFA. Restreindre les portails admin aux emplacements de confiance/identités privilégiées. Utiliser des contrôles JIT pour les identifiants privilégiés. Appliquer le principe du moindre privilège. Hardener les comptes privilégiés pour éviter leur exposition sur des endpoints non-PAW. Inclure la révocation de tokens/clés d'accès, la revue des enregistrements MFA, des changements d'authentification et des appareils nouvellement inscrits dans les playbooks de réponse. Appliquer des contrôles de posture pour les appareils (certificat, OS, version, EDR). Surveiller les hôtes bastion/VMs non autorisés. Renforcer les politiques de jonction de domaine (Entra/AD). Examiner les logs d'authentification pour les noms d'hôte par défaut. Limiter l'utilisation des comptes locaux pour l'authentification réseau. Désactiver/restreindre l'accès distant aux partages admin/cachés. Appliquer des règles de pare-feu locales pour bloquer SMB, RDP, WinRM, PowerShell, WMI entrants. Restreindre l'utilisation des comptes de service/privilégiés pour l'authentification distante via GPO (Deny log on locally, Deny log on through Remote Desktop Services, Deny access to this computer from network, Deny log on as a batch, Deny log on as a service). Désactiver la modification des configurations d'agent VPN par les utilisateurs finaux. Assurer la journalisation des changements de configuration VPN. Envisager un VPN "Always-On" pour les appareils gérés. Isoler et restreindre l'accès aux systèmes PAM. Réduire le périmètre des comptes ayant accès aux systèmes PAM et exiger la MFA. Appliquer le RBAC dans les systèmes PAM. Suivre le principe JIT pour les identifiants stockés dans les systèmes PAM. Isoler et restreindre l'accès à l'infrastructure de virtualisation (ESXi, vCenter). Assurer l'isolation, la sécurisation et l'immutabilité des sauvegardes VM. Découpler l'authentification admin des plateformes de virtualisation de l'IdP centralisé. Faire pivoter proactivement les mots de passe root/admin locaux pour les identités privilégiées associées aux plateformes de virtualisation. Utiliser une MFA plus forte et la lier au SSO local pour tout accès admin à l'infra de virtualisation. Appliquer des mots de passe aléatoires pour les identités root/admin locales. Désactiver/restreindre l'accès SSH aux plateformes de virtualisation. Activer le mode verrouillé sur tous les hôtes ESXi. Renforcer le monitoring des tentatives d'authentification/activités suspectes sur les plateformes de virtualisation. Utiliser des identifiants uniques et séparés (non intégrés à l'IdP) pour l'accès/gestion de l'infra de sauvegarde et appliquer la MFA. S'assurer que les serveurs de sauvegarde sont isolés et résident dans un réseau dédié. Les sauvegardes doivent être dans une solution immuable si possible. Mettre en place des contrôles d'accès pour restreindre le trafic entrant vers les interfaces admin de l'infra de sauvegarde. Valider périodiquement la protection/intégrité des sauvegardes par simulation (red teaming). Segmenter l'accès admin aux plateformes d'outils de sécurité endpoint. Réduire le périmètre des identités ayant la capacité de créer, modifier ou supprimer des GPO. Si Intune est utilisé, appliquer des politiques d'accès nécessitant une approbation multi-admin. Surveiller les accès non autorisés aux technologies EDR et de gestion des correctifs. Surveiller le déploiement de scripts/applications via les technologies EDR et de gestion des correctifs. Revoir les exécutables, processus, chemins, applications autorisés. Inventaire des applications installées sur les endpoints et vérification des installations non autorisées d'outils RAT/reconnaissance. Surveiller et examiner les configurations de ressources cloud (nouvelles ressources, services exposés). Surveiller les créations/modifications de règles de groupe de sécurité réseau (NSG), règles de pare-feu, ressources exposées publiquement. Surveiller la création de clés/identifiants programmatiques (clés d'accès). Utiliser le balayage de vulnérabilités pour identifier les domaines/IPs/CIDR exposés publiquement. Appliquer une authentification forte (MFA résistante au hameçonnage) pour les applications/services publics. Pour les données/applications sensibles, restreindre la connectivité aux environnements cloud/SaaS à des plages d'IP spécifiques (de confiance). Bloquer les nœuds de sortie TOR et les plages d'IP VPS. Restreindre l'accès à l'infrastructure de services de confiance (TSI) aux segments réseau internes/durcis ou aux PAW. Créer des détections basées sur le monitoring du trafic réseau vers le TSI et alerter sur les anomalies. Restreindre les communications sortantes de tous les serveurs, en particulier ceux du TSI, des contrôleurs de domaine AD et des serveurs d'applications/données critiques. Bloquer le trafic sortant vers des noms de domaine/adresses IP malveillants et ceux associés aux outils d'accès à distance (RAT). S'assurer que les sites/portails contenant de la documentation sensible (provisionnement, MFA, schémas réseau, identifiants partagés) ont des restrictions d'accès. Balayer les documents/feuilles de calcul qui pourraient contenir des identifiants partagés. Implémenter des règles d'alerte sur les endpoints avec EDR pour l'exécution d'outils de reconnaissance connus (ADRecon, ADExplorer, SharpHound). Si une solution de monitoring d'identité est utilisée, s'assurer que les règles de détection et les alertes pour la reconnaissance/découverte sont activées. Mettre en place un mécanisme automatisé pour surveiller en continu les enregistrements de domaine imitant les conventions de nommage de l'organisation ([VotreNomOrganisation]-helpdesk.com, [VotreNomOrganisation]-SSO.com). Examiner les logs pour identifier les événements liés à l'enregistrement/ajout de nouveaux appareils/méthodes MFA. Vérifier la légitimité des nouveaux enregistrements par rapport au comportement utilisateur attendu. Contacter les utilisateurs si de nouveaux enregistrements sont détectés. Examiner les politiques organisationnelles concernant les outils de communication (Microsoft Teams). N'autoriser que les domaines externes de confiance pour les fournisseurs/partenaires attendus. Si les domaines externes ne peuvent pas être bloqués, créer une base de référence des domaines de confiance et alerter sur les nouveaux domaines qui tentent de contacter les employés. Sensibiliser les employés à contacter directement le help desk s'ils reçoivent des appels/messages suspects. Implémenter des détections pour l'authentification à partir d'emplacements inhabituels (proxies, VPNs). Surveiller les tentatives de changement de méthodes/critères d'authentification. Surveiller les anomalies d'authentification basées sur les tactiques d'ingénierie sociale. Pour Entra ID, surveiller les modifications des Trusted Named Locations. Pour Entra ID, surveiller les changements des politiques d'accès conditionnel qui imposent la MFA, en se concentrant sur les exclusions. S'assurer que le SOC a une visibilité sur les rejeux de tokens ou les logins suspects et déclencher une réauthentification si nécessaire. Pour Entra ID, surveiller l'abus potentiel de la fédération d'identité (vérifier les domaines fédérés, examiner la configuration de fédération, surveiller la création de nouveaux domaines/changement de méthode d'authentification). Durcir tous les comptes admin, portails et accès programmatiques. Sensibiliser les utilisateurs aux tactiques d'ingénierie sociale spécifiques à UNC3944/DragonForce (SMS phishing, appels téléphoniques, MFA fatigue, usurpation d'identité sur Teams, menaces de doxxing).

## 🌕 Luna Moth (Silent Ransom Group) ciblant les entreprises américaines par hameçonnage de rappel (Callback Phishing)
Le groupe d'extorsion de données Luna Moth, également connu sous le nom de Silent Ransom Group, a intensifié ses campagnes d'hameçonnage de rappel ciblant les institutions juridiques et financières aux États-Unis. Leur objectif principal est le vol de données suivi d'extorsion. Luna Moth utilisait auparavant des campagnes BazarCall pour obtenir un accès initial pour Ryuk et Conti. Après la dissolution de Conti, ils ont formé le Silent Ransom Group (SRG). Les attaques actuelles impliquent l'usurpation d'identité du support informatique par email, faux sites et appels téléphoniques, s'appuyant uniquement sur l'ingénierie sociale sans déployer de ransomware sur les machines des victimes. Ils incitent les victimes à installer des logiciels légitimes de surveillance et de gestion à distance (RMM) à partir de faux sites d'assistance, leur donnant ainsi accès aux systèmes. Les données volées sont ensuite exfiltrées et utilisées pour faire chanter les organisations.

* Publication date : 2025/05/05
* 🗺️ Source : https://www.bleepingcomputer.com/news/security/luna-moth-extortion-hackers-pose-as-it-help-desks-to-breach-us-firms/
* 🧑‍💻 Threat Actor : Luna Moth (Silent Ransom Group)
* 🎯 Threat Target : Institutions juridiques et financières aux États-Unis (mentionne également US Customs and Border Protection, Coinbase, diverses institutions financières comme Scotiabank via les données compromises).
* 🦹 Threat Tactic : Hameçonnage (Phishing de rappel), Ingénierie Sociale (usurpation d'identité IT help desk), Vol de données, Extorsion.
* 🛠️ Threat Tools : Logiciels RMM légitimes (Syncro, SuperOps, Zoho Assist, Atera, AnyDesk, Splashtop), WinSCP (via SFTP), Rclone (cloud syncing).
* 🛡️ Security Recommandations : Ajouter les domaines de hameçonnage et les adresses IP associés à une liste de blocage. Envisager de restreindre l'exécution des outils RMM qui ne sont pas utilisés dans l'environnement de l'organisation.
* 🚩 Indicator of Compromise :
    * DOMAIN : helpdesk[.]com (utilise des modèles de typosquatted patterns comme [company_name]-helpdesk.com et [company_name]helpdesk.com)

## 🧛‍♂️ Darcula PhaaS : Plateforme d'Hameçonnage-as-a-Service pour le Vol de Cartes de Crédit
La plateforme d'hameçonnage-as-a-service (PhaaS) Darcula a volé 884 000 cartes de crédit suite à 13 millions de clics sur des liens malveillants envoyés par SMS à des cibles mondiales sur sept mois (2023-2024). Darcula cible les utilisateurs Android et iPhone dans plus de 100 pays, utilisant 20 000 domaines pour usurper l'identité de marques connues. Initialement remarquée pour son utilisation de RCS et iMessage, la plateforme a évolué pour inclure la génération automatique de kits de hameçonnage, des fonctionnalités furtives, un convertisseur carte de crédit vers carte virtuelle, et l'intégration de l'IA générative pour créer des escroqueries personnalisées. L'opération utilise un toolkit appelé 'Magic Cat'. Les chercheurs ont infiltré un groupe Telegram associé, identifiant environ 600 opérateurs (clients de la plateforme) et traçant l'opération jusqu'à un individu et une entreprise en Chine.

* Publication date : 2025/05/05
* 🗺️ Source : https://www.bleepingcomputer.com/news/security/darcula-phaas-steals-884-000-credit-cards-via-phishing-texts/, https://cybersecuritynews.com/darcula-phaas-stolen-884000-credit-card-details/
* 🧑‍💻 Threat Actor : Opération Darcula (Silent Ransom Group mentionné dans le texte mais il s'agit d'une erreur d'attribution, l'acteur est le collectif Darcula), Opérateurs (env. 600 clients), 'x66/Kris' (utilisateur basé en Thaïlande, potentiel rôle hiérarchique élevé).
* 🎯 Threat Target : Utilisateurs Android et iPhone dans plus de 100 pays, victimes d'escroqueries simulant des amendes de péage ou des notifications d'expédition de colis.
* 🦹 Threat Tactic : Hameçonnage-as-a-Service (PhaaS), Smishing (hameçonnage par SMS via RCS, iMessage), Usurpation de marque, Vol d'identifiants et de cartes de crédit, Extorsion de données (via des sites de hameçonnage imitant des pages de connexion/paiement).
* 🛠️ Threat Tools : Plateforme Darcula, Toolkit 'Magic Cat', Faux sites de hameçonnage (20 000 domaines), Logiciels/matériel de ferme de SIM.
* 🛡️ Security Recommandations : Être vigilant face aux messages texte/emails inattendus demandant des informations personnelles ou de cliquer sur des liens. Vérifier l'authenticité des communications directement avec l'entreprise concernée via ses canaux officiels. Utiliser la MFA. Ne pas installer de logiciels ou fournir d'informations sensibles via des liens ou des appels non sollicités. Se méfier des offres trop belles pour être vraies. Les forces de l'ordre ont été informées.

## 🍼 Nouvelle technique de contournement d'EDR ("Bring Your Own Installer") utilisée dans des attaques par ransomware Babuk
Une nouvelle technique de contournement d'EDR, surnommée "Bring Your Own Installer", est exploitée pour désactiver la fonction de protection contre l'altération de SentinelOne, permettant ainsi le déploiement du ransomware Babuk. Cette technique abuse du processus de mise à jour de l'agent SentinelOne lui-même. Les attaquants exécutent un programme d'installation légitime de SentinelOne, qui termine les processus de l'agent en cours d'exécution juste avant l'écrasement des fichiers, puis terminent de force le processus d'installation, laissant l'appareil sans protection. Cette technique a été découverte par les chercheurs de Stroz Friedberg lors d'une réponse à incident impliquant une attaque par ransomware. Elle ne repose pas sur des outils ou des pilotes tiers.

* Publication date : 2025/05/05
* 🗺️ Source : https://www.bleepingcomputer.com/news/security/new-bring-your-own-installer-edr-bypass-used-in-ransomware-attack/, https://cybersecuritynews.com/threat-actor-bypass-sentinelone-edr/
* 🧑‍💻 Threat Actor : Acteurs de la menace utilisant le ransomware Babuk (affiliés), potentiellement ceux qui ont obtenu un accès administratif via une vulnérabilité antérieure.
* 🎯 Threat Target : Appareils exécutant l'agent EDR SentinelOne, entreprises victimes du ransomware Babuk.
* 🦹 Threat Tactic : Contournement d'EDR ("Bring Your Own Installer"), Déploiement de Ransomware.
* 🛠️ Threat Tools : Programme d'installation légitime de SentinelOne, Ransomware Babuk, processus Windows Installer ("msiexec.exe").
* 🛡️ Security Recommandations : Les clients de SentinelOne doivent activer le paramètre "Online Authorization" dans les paramètres de politique Sentinel. Ce paramètre exige une approbation de la console de gestion SentinelOne avant que les mises à niveau, les rétrogradations ou les désinstallations locales de l'agent puissent avoir lieu. Auditer les logs pour détecter les tentatives d'interrompre le processus msiexec.exe après l'arrêt des services de l'agent SentinelOne.

# VULNERABILITIES

## 🐛 Vulnérabilité Critique d'Injection SQL dans la Librairie PHP ADOdb (CVE-2025-46337)
Une vulnérabilité critique d'injection SQL (CVSS 10.0) a été découverte dans ADOdb, une bibliothèque PHP d'abstraction de base de données largement utilisée. La faille réside dans la méthode `pg_insert_id()` du pilote PostgreSQL. Une échappement incorrect d'un paramètre de requête permet à un attaquant d'exécuter des commandes SQL arbitraires si la fonction est appelée avec des données fournies par l'utilisateur. Cela peut permettre le vol, la suppression de données, voire l'exécution de code à distance dans le pire scénario d'utilisation.

* Publication date : 2025/05/05
* 🗺️ Source : https://securityonline.info/critical-sql-injection-vulnerability-found-in-adodb-php-library-cve-2025-46337-cvss-10-0/
* 🐞 CVE : [CVE-2025-46337](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-46337)
* 📦 CVE IMPACTED PRODUCT : ADOdb PHP library (versions <= 5.22.8)
* ⚖️ CVSS : 10.0
* 🛡️ Security Recommandations : Mettre à niveau vers ADOdb version 5.22.9 ou ultérieure. Si la mise à niveau immédiate n'est pas possible, ne passer que des données contrôlées au paramètre $fieldname de la méthode pg_insert_id(), ou l'échapper d'abord avec pg_escape_identifier().

## 🔐 Vulnérabilités Critiques dans les Panneaux d'Alarme Honeywell MB-Secure (CVE-2025-2605)
Honeywell a publié un avis urgent concernant une vulnérabilité critique (CVSS 9.9) dans ses panneaux de contrôle d'alarme MB-Secure et MB-Secure PRO. La faille, une injection de commande OS, permet à un attaquant disposant d'un accès limité d'exécuter des commandes OS non autorisées avec des privilèges élevés (CAPEC-122).

* Publication date : 2025/05/06
* 🗺️ Source : https://securityonline.info/cve-2025-2605-cvss-9-9-critical-vulnerability-found-in-honeywell-mb-secure-alarm-panels/
* 🐞 CVE : [CVE-2025-2605](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-2605)
* 📦 CVE IMPACTED PRODUCT : Honeywell MB-Secure (V11.04 à V12.52), Honeywell MB-Secure PRO (V01.06 à V03.08)
* ⚖️ CVSS : 9.9
* ❓ MITRE ATT&CK : CAPEC-122: Privilege Abuse
* 🛡️ Security Recommandations : Mettre à niveau vers MB-Secure version V12.53 et MB-Secure PRO version V03.09. Ces mises à jour sont destinées au personnel qualifié avec des identifiants administratifs.

## 💥 Vulnérabilités Multiples Activement Exploitées dans Langflow (CVE-2025-3248), Android/FreeType (CVE-2025-27363), et Commvault (CVE-2025-34028)
Plusieurs vulnérabilités critiques et élevées, activement exploitées dans la nature, ont été signalées.
Une vulnérabilité critique (CVSS 9.8), **CVE-2025-3248**, dans la plateforme open-source Langflow permet l'exécution de code arbitraire à distance sans authentification via l'endpoint `/api/v1/validate/code`. La CISA l'a ajoutée à son catalogue KEV.
Une vulnérabilité élevée (CVSS 8.1), **CVE-2025-27363**, dans le composant Système d'Android et la librairie FreeType, permettant l'exécution de code localement sans privilèges supplémentaires. Google a publié des correctifs et indique qu'elle est sous exploitation limitée et ciblée.
Une vulnérabilité de sévérité maximale (CVSS 10.0), **CVE-2025-34028**, impactant Commvault Command Center via une faille de path traversal (traversée de chemins) permet à un attaquant non authentifié d'exécuter du code arbitraire. La CISA l'a ajoutée à son catalogue KEV.

* Publication date : 2025/05/06, 2025/05/05
* 🗺️ Source : https://thehackernews.com/2025/05/critical-langflow-flaw-added-to-cisa.html, https://thehackernews.com/2025/05/google-fixes-actively-exploited-android.html, https://www.security.nl/posting/886659/Google+komt+met+Android-updates+voor+aangevallen+FreeType-lek?channel=rss, https://securityonline.info/android-security-bulletin-may-2025-multi-vulnerabilities-including-actively-exploited-cve-2025-27363/, https://securityonline.info/langflow-under-attack-cisa-warns-of-active-exploitation-of-cve-2025-3248/, https://thehackernews.com/2025/05/commvault-cve-2025-34028-added-to-cisa.html
* 🐞 CVE : [CVE-2025-3248](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-3248), [CVE-2025-27363](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27363), [CVE-2025-34028](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-34028)
* 📦 CVE IMPACTED PRODUCT : Langflow (la plupart des versions, corrigé en 1.3.0), Android System component (Android 13, 14, 15), FreeType library (<= 2.13.0), Commvault Command Center (11.38 Innovation Release, versions 11.38.0 à 11.38.19)
* ⚖️ CVSS : 9.8 (CVE-2025-3248), 8.1 (CVE-2025-27363), 10.0 (CVE-2025-34028)
* 🕵️ Exploitation : CVE-2025-3248 (Activement exploitée), CVE-2025-27363 (Exploitation limitée, ciblée), CVE-2025-34028 (Activement exploitée)
* 🛡️ Security Recommandations :
    *   Pour Langflow : Mettre à niveau vers la version 1.3.0 ou ultérieure. Appliquer les correctifs requis par la CISA avant le 26 mai 2025 pour les agences fédérales américaines.
    *   Pour Android : Installer les mises à jour de sécurité Android de mai 2025 (niveaux de patch 2025-05-05 ou ultérieurs). Mettre à niveau FreeType vers une version supérieure à 2.13.0.
    *   Pour Commvault Command Center : Mettre à niveau vers les versions 11.38.20, 11.38.25 ou ultérieures. Appliquer les correctifs requis par la CISA avant le 23 mai 2025 pour les agences fédérales américaines.
* 🚩 Indicator of Compromise :
    * IPv4 : 10[.]0[.]220[.]200 (exemple PoC pour Langflow)
    * URL : hxxp[:]//10[.]0[.]220[.]200[:]8000/api/v1/validate/code (exemple PoC pour Langflow)

## 🔓 Vulnérabilité Critique dans le Plugin WordPress OttoKit (CVE-2025-27007)
Une vulnérabilité critique (CVSS 9.8) dans le plugin WordPress populaire OttoKit (plus de 100 000 installations) permet une escalade de privilèges non authentifiée. La faille réside dans la fonction `create_wp_connection` de l'API REST du plugin. Un attaquant peut obtenir le contrôle total du site, y compris la création de comptes administrateur, simplement en connaissant le nom d'utilisateur de l'administrateur, et en contournant l'authentification si aucun mot de passe d'application n'est défini. L'exploitation a été observée activement dans l'heure suivant la divulgation.

* Publication date : 2025/05/06
* 🗺️ Source : https://securityonline.info/cve-2025-27007-critical-ottokit-wordpress-plugin-flaw-exploited-after-disclosure-100k-sites-at-risk/
* 🐞 CVE : [CVE-2025-27007](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27007)
* 📦 CVE IMPACTED PRODUCT : OttoKit WordPress plugin (versions <= 1.0.82)
* ⚖️ CVSS : 9.8
* 🕵️ Exploitation : Activement exploitée.
* 🛡️ Security Recommandations : Mettre à niveau vers OttoKit version 1.0.83 ou ultérieure. Examiner les logs d'accès pour les requêtes suspectes vers `/wp-json/sure-triggers/v1/connection/create-wp-connection` et `/wp-json/sure-triggers/v1/automation/action`, ainsi que les payloads contenant `"type_event": "create_user_if_not_exists"`. Auditer les comptes utilisateur pour détecter les nouvelles entrées d'administrateur inattendues.

## 🔐 Vulnérabilité Critique dans OpenCTI (CVE-2025-24977)
Une vulnérabilité critique (CVSS 9.1) a été découverte dans la plateforme open source de Cyber Threat Intelligence OpenCTI. Avant la version 6.4.11, tout utilisateur disposant de la capacité `manage customizations` pouvait exécuter des commandes sur l'infrastructure sous-jacente et accéder aux secrets côté serveur en abusant des webhooks. Cela permet d'obtenir un shell root dans un conteneur et d'ouvrir l'environnement d'infrastructure à d'autres attaques.

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-24977
* 🐞 CVE : [CVE-2025-24977](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24977)
* 📦 CVE IMPACTED PRODUCT : OpenCTI (versions antérieures à 6.4.11)
* ⚖️ CVSS : 9.1
* 🛡️ Security Recommandations : Mettre à niveau vers OpenCTI version 6.4.11 ou ultérieure.

## ⚠️ Vulnérabilités Critiques/Élevées dans IBM Cognos Analytics (CVE-2024-51466, CVE-2024-40695)
IBM a publié des mises à jour de sécurité pour corriger deux vulnérabilités affectant sa plateforme IBM Cognos Analytics. La plus sévère, **CVE-2024-51466** (CVSS 9.0), est une injection EL (Expression Language) permettant à un attaquant distant d'exposer des informations sensibles, de consommer des ressources mémoire et/ou de provoquer un crash du serveur. La seconde, **CVE-2024-40695** (CVSS 8.0), résulte d'une validation inadequate des téléversements de fichiers via l'interface web, permettant l'upload de fichiers exécutables malveillants et potentiellement l'exécution de code à distance.

* Publication date : 2025/05/06
* 🗺️ Source : https://securityonline.info/critical-ibm-cognos-analytics-vulnerabilities-demand-urgent-patching/
* 🐞 CVE : [CVE-2024-51466](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-51466), [CVE-2024-40695](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40695)
* 📦 CVE IMPACTED PRODUCT : IBM Cognos Analytics (12.0.0 – 12.0.4, 11.2.0 – 11.2.4 FP4)
* ⚖️ CVSS : 9.0 (CVE-2024-51466), 8.0 (CVE-2024-40695)
* 🛡️ Security Recommandations : Appliquer les correctifs : 12.0.4 Interim Fix 1 pour les versions 12.0.0 à 12.0.4, et 11.2.4 FP5 pour les versions 11.2.0 à 11.2.4 FP4. IBM recommande fortement d'appliquer la mise à niveau immédiatement.

## 🐞 Vulnérabilités Multiples dans SeaCMS v13.3
Trois vulnérabilités critiques ont été découvertes dans SeaCMS v13.3. **CVE-2025-44074** et **CVE-2025-44072** sont des vulnérabilités d'injection SQL via les composants `admin_topic.php` et `admin_manager.php` respectivement (CVSS 9.8). **CVE-2025-44071** est une vulnérabilité d'exécution de code à distance (RCE) via le composant `phomebak.php` (CVSS 9.8), permettant l'exécution de code arbitraire via une requête craftée.

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-44074, https://cvefeed.io/vuln/detail/CVE-2025-44072, https://cvefeed.io/vuln/detail/CVE-2025-44071
* 🐞 CVE : [CVE-2025-44074](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-44074), [CVE-2025-44072](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-44072), [CVE-2025-44071](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-44071)
* 📦 CVE IMPACTED PRODUCT : SeaCMS (v13.3)
* ⚖️ CVSS : 9.8 (pour chaque CVE)
* 🛡️ Security Recommandations : Aucune correction ou mise à jour spécifique mentionnée dans les sources, au-delà de la divulgation. Il est recommandé de restreindre l'accès aux panneaux d'administration et de surveiller les activités suspectes sur les fichiers mentionnés (`admin_topic.php`, `admin_manager.php`, `phomebak.php`).

## 🖱️ Vulnérabilités Élevées/Critiques dans Google Chrome/Edge (CVE-2025-4096, CVE-2025-4050)
Google a corrigé plusieurs vulnérabilités dans Chrome, affectant également Microsoft Edge Chromium. **CVE-2025-4096** est un dépassement de tampon (Heap Buffer Overflow) dans HTML (CVSS 8.8, sévérité Haute pour Chromium). **CVE-2025-4050** est un accès hors limites (Out-of-Bounds Access) dans DevTools (CVSS 8.8, sévérité Moyenne pour Chromium). Ces failles pourraient permettre à un attaquant distant, via une page HTML craftée ou des gestes d'interface utilisateur spécifiques, d'exploiter la corruption du tas. Des PoC publiques sont disponibles.

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-4096, https://cvefeed.io/vuln/detail/CVE-2025-4050
* 🐞 CVE : [CVE-2025-4096](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4096), [CVE-2025-4050](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4050)
* 📦 CVE IMPACTED PRODUCT : Google Chrome (antérieur à 136.0.7103.59), Microsoft Edge Chromium (versions basées sur les versions Chrome vulnérables)
* ⚖️ CVSS : 8.8 (pour chaque CVE)
* 🕵️ Exploitation : PoC publics disponibles.
* 🛡️ Security Recommandations : Mettre à jour Google Chrome vers la version 136.0.7103.59 ou ultérieure et Microsoft Edge Chromium vers la version corrigée correspondante.

## 🔄 Vulnérabilités Critiques dans Tenda AC9 (CVE-2025-45042) et Output Messenger (CVE-2025-27920)
Deux vulnérabilités critiques ont été signalées. **CVE-2025-45042** (CVSS 9.8) est une vulnérabilité d'injection de commande dans Tenda AC9 v15.03.05.14 via la fonction Telnet. **CVE-2025-27920** (CVSS 9.8) est une vulnérabilité de traversée de répertoire (Directory Traversal) dans Output Messenger avant la version 2.0.63, due à une gestion incorrecte des chemins de fichiers, permettant potentiellement la fuite de configuration ou l'accès arbitraire aux fichiers.

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-45042, https://cvefeed.io/vuln/detail/CVE-2025-27920
* 🐞 CVE : [CVE-2025-45042](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-45042), [CVE-2025-27920](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27920)
* 📦 CVE IMPACTED PRODUCT : Tenda AC9 (v15.03.05.14), Output Messenger (avant 2.0.63)
* ⚖️ CVSS : 9.8 (pour chaque CVE)
* 🛡️ Security Recommandations : Pour Tenda AC9, désactiver ou restreindre l'accès à la fonction Telnet si elle n'est pas essentielle. Pour Output Messenger, mettre à niveau vers la version 2.0.63 ou ultérieure.

## 🔑 Vulnérabilités Critiques d'Authentification/PrivEsc dans brcc (CVE-2025-45616), yaoqishan (CVE-2025-45615) et BuddyBoss (CVE-2025-1909)
Trois vulnérabilités critiques liées à l'authentification ou l'escalade de privilèges ont été signalées. **CVE-2025-45616** (CVSS 9.8) est un contournement d'authentification dans l'API `/admin/**` de brcc v1.2.0. **CVE-2025-45615** (CVSS 9.8) est une escalade de privilèges administrative non authentifiée dans l'API `/admin/` de yaoqishan v0.0.1-SNAPSHOT. **CVE-2025-1909** (CVSS 9.8) est un contournement d'authentification dans le plugin WordPress BuddyBoss Platform Pro <= 2.7.01 via Apple OAuth. Ces failles permettent aux attaquants d'obtenir des droits d'administration ou de se connecter en tant qu'utilisateur existant (y compris administrateur).

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-45616, https://cvefeed.io/vuln/detail/CVE-2025-45615, https://cvefeed.io/vuln/detail/CVE-2025-1909
* 🐞 CVE : [CVE-2025-45616](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-45616), [CVE-2025-45615](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-45615), [CVE-2025-1909](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1909)
* 📦 CVE IMPACTED PRODUCT : brcc (v1.2.0), yaoqishan (v0.0.1-SNAPSHOT), BuddyBoss Platform Pro plugin for WordPress (versions <= 2.7.01)
* ⚖️ CVSS : 9.8 (pour chaque CVE)
* 🛡️ Security Recommandations : Pour brcc et yaoqishan, restreindre l'accès à l'API /admin/ si possible et surveiller les accès non autorisés. Pour BuddyBoss Platform Pro, mettre à niveau vers une version supérieure à 2.7.01.

## 💾 Vulnérabilités Critiques/Élevées d'Injection SQL dans Kashipara Online Service Management Portal (CVE-2025-45322, CVE-2025-45321)
Le portail de gestion de services en ligne Kashipara V1.0 est affecté par deux vulnérabilités d'injection SQL. **CVE-2025-45322** (CVSS 9.8) via le paramètre `checkid` dans `CheckStatus.php`, et **CVE-2025-45321** (CVSS 8.8) via le paramètre `rPassword` dans `/osms/Requester/Requesterchangepass.php`. Ces failles permettent l'injection SQL.

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-45322, https://cvefeed.io/vuln/detail/CVE-2025-45321
* 🐞 CVE : [CVE-2025-45322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-45322), [CVE-2025-45321](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-45321)
* 📦 CVE IMPACTED PRODUCT : kashipara Online Service Management Portal (V1.0)
* ⚖️ CVSS : 9.8 (CVE-2025-45322), 8.8 (CVE-2025-45321)
* 🛡️ Security Recommandations : Assainir et valider toutes les entrées utilisateur, en particulier les paramètres mentionnés (`checkid`, `rPassword`), avant de les utiliser dans les requêtes SQL. Utiliser des requêtes paramétrées ou des procédures stockées.

## 🌐 Vulnérabilités Élevées de Buffer Overflow dans Tenda AC1206 (CVE-2025-4299, CVE-2025-4298)
Plusieurs vulnérabilités de dépassement de tampon (Buffer Overflow) classées comme critiques/élevées (CVSS 8.8) ont été trouvées dans Tenda AC1206 jusqu'à la version 15.03.06.23. **CVE-2025-4299** affecte la fonction `setSchedWifi` et **CVE-2025-4298** affecte la fonction `formSetCfm`. Ces vulnérabilités peuvent être initiées à distance et des exploits publics sont disponibles.

* Publication date : 2025/05/06
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-4299, https://cvefeed.io/vuln/detail/CVE-2025-4298
* 🐞 CVE : [CVE-2025-4299](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4299), [CVE-2025-4298](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4298)
* 📦 CVE IMPACTED PRODUCT : Tenda AC1206 (jusqu'à 15.03.06.23)
* ⚖️ CVSS : 8.8 (pour chaque CVE)
* 🕵️ Exploitation : Exploit public disponible.
* 🛡️ Security Recommandations : Vérifier si une mise à jour du firmware est disponible pour Tenda AC1206 et l'appliquer. Restreindre l'accès administratif au routeur à des réseaux de confiance.
* 🚩 Indicator of Compromise :
    * URL : hxxps[:]//github[.]com/CH13hh/tmp_store_cc/blob/main/AC1206/AC1206setSchedWifi/setSchedWifi[.]md (PoC pour CVE-2025-4299)
    * URL : hxxps[:]//github[.]com/CH13hh/tmp_store_cc/blob/main/AC1206/AC1206formSetCfm/formSetCfm[.]md (PoC pour CVE-2025-4298)

## 📂 Vulnérabilité Élevée de Téléversement de Fichiers dans le Plugin WordPress External Image Replace (CVE-2025-4279)
Le plugin WordPress External Image Replace, versions <= 1.0.8, est vulnérable au téléversement arbitraire de fichiers (CVSS 8.8). La faille réside dans la fonction `external_image_replace_get_posts::replace_post` en raison d'une validation manquante du type de fichier. Cela permet aux attaquants authentifiés, avec des permissions de niveau contributeur ou supérieur, de téléverser des fichiers arbitraires sur le serveur, rendant possible l'exécution de code à distance.

* Publication date : 2025/05/05
* 🗺️ Source : https://cvefeed.io/vuln/detail/CVE-2025-4279
* 🐞 CVE : [CVE-2025-4279](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4279)
* 📦 CVE IMPACTED PRODUCT : External image replace plugin for WordPress (versions <= 1.0.8)
* ⚖️ CVSS : 8.8
* 🛡️ Security Recommandations : Mettre à niveau le plugin External Image Replace vers la version corrigée (aucune version corrigée n'est explicitement mentionnée dans la source, mais il faut rechercher une version supérieure à 1.0.8). Restreindre les privilèges des utilisateurs au strict minimum nécessaire.

## 🖥️ Vulnérabilité Élevée d'Escalade de Privilèges dans Webmin (CVE-2025-2774)
Une vulnérabilité de sécurité critique/élevée (CVSS 8.8) a été découverte dans Webmin, un outil d'administration système basé sur le web. La faille, **CVE-2025-2774**, est une injection CRLF dans la gestion des requêtes CGI qui permet aux attaquants authentifiés d'escalader leurs privilèges et d'exécuter du code avec des droits root sur les serveurs affectés (versions antérieures à 2.302).

* Publication date : 2025/05/05
* 🗺️ Source : https://cybersecuritynews.com/webmin-vulnerability-escalate-privileges/
* 🐞 CVE : [CVE-2025-2774](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-2774)
* 📦 CVE IMPACTED PRODUCT : Webmin (versions antérieures à 2.302)
* ⚖️ CVSS : 8.8
* 🛡️ Security Recommandations : Mettre à jour Webmin vers la version 2.302 ou ultérieure. Restreindre l'accès à Webmin aux réseaux de confiance et appliquer des pratiques d'authentification forte. Examiner les logs système pour détecter les activités inhabituelles. Adhérer aux principes du moindre privilège.

## 칩셋 Vulnérabilités Multiples dans les Chipsets MediaTek
MediaTek a publié un bulletin de sécurité pour mai 2025, détaillant plusieurs vulnérabilités affectant une large gamme de ses chipsets utilisés dans les smartphones, tablettes, appareils AIoT, systèmes audio et TV. Parmi les six CVE signalées, une est classée haute sévérité (**CVE-2025-20666**, CVSS non fourni mais décrit comme élevé), une assertion atteignable dans le composant Modem pouvant conduire à un déni de service (DoS) à distance si un appareil se connecte à une fausse station de base. Cinq autres sont de sévérité moyenne (CVSS non fournis mais décrits comme moyens), incluant des écritures hors limites, une force de chiffrement inadequate, une validation de certificat incorrecte et une exposition d'informations.

* Publication date : 2025/05/05
* 🗺️ Source : https://cybersecuritynews.com/mediatek-patches-multiple-flaws/, https://securityonline.info/mediatek-may-2025-security-bulletin-chipset-vulnerabilities-disclosed/
* 🐞 CVE : [CVE-2025-20666](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20666), [CVE-2025-20667](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20667), [CVE-2025-20671](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20671), [CVE-2025-20668](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20668), [CVE-2025-20670](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20670), [CVE-2025-20665](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20665)
* 📦 CVE IMPACTED PRODUCT : Chipsets MediaTek (MT6833, MT6877, MT6893, et plus de 30 autres) affectés par diverses CVE et versions de firmware/Android (Modem NR15, Modem LR12A, LR13, NR15, NR16, NR17, NR17R firmware, Android 13.0, 14.0, 15.0).
* ⚖️ CVSS : N/A (Décrit comme Haute/Moyenne sévérité)
* 🛡️ Security Recommandations : Installer les dernières mises à jour logicielles fournies par les fabricants d'appareils dès qu'elles sont disponibles.

## 🍏 Vulnérabilités Corrigées Potentiellement Critiques/Ver dans Apple AirPlay
Des chercheurs en cybersécurité ont divulgué une série de vulnérabilités désormais corrigées dans le protocole AirPlay d'Apple. Ces failles, collectivement nommées AirBorne, si exploitées avec succès, pourraient permettre à un attaquant de prendre le contrôle des appareils compatibles. Certaines vulnérabilités, comme **CVE-2025-24252** et **CVE-2025-24132**, pourraient être enchaînées pour créer un exploit RCE (Remote Code Execution) sans clic et "wormable", capable de se propager sur le réseau local. D'autres failles permettent le contournement des listes de contrôle d'accès (ACL), la lecture de fichiers arbitraires locaux, la divulgation d'informations, les attaques de type "adversary-in-the-middle" (AitM) et le déni de service (DoS).

* Publication date : 2025/05/05
* 🗺️ Source : https://thehackernews.com/2025/05/wormable-airplay-flaws-enable-zero.html
* 🐞 CVE : [CVE-2025-24252](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24252), [CVE-2025-24132](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24132), [CVE-2025-24206](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24206), [CVE-2025-24271](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24271), [CVE-2025-24137](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24137), [CVE-2025-24270](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24270), [CVE-2025-24251](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24251), [CVE-2025-31197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-31197), [CVE-2025-30445](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-30445), [CVE-2025-31203](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-31203), [CVE-2025-30422](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-30422)
* 📦 CVE IMPACTED PRODUCT : Appareils Apple et tiers prenant en charge le protocole AirPlay, iOS (versions < 18.4), iPadOS (versions < 18.4 et < 17.7.6), macOS (versions < Sequoia 15.4, < Sonoma 14.7.5, < Ventura 13.7.5), tvOS (versions < 18.4), visionOS (versions < 2.4), AirPlay audio SDK (< 2.7.1), AirPlay video SDK (< 3.6.0.126), CarPlay Communication Plug-in (< R18.1).
* ⚖️ CVSS : N/A (Non explicitement fourni dans l'article, mais impact décrit comme RCE sans clic, potentiellement critique)
* 🛡️ Security Recommandations : Mettre à jour immédiatement tous les appareils Apple et les appareils tiers prenant en charge AirPlay vers les dernières versions logicielles corrigées (iOS 18.4+, iPadOS 18.4+ ou 17.7.6+, macOS Sequoia 15.4+, macOS Sonoma 14.7.5+, macOS Ventura 13.7.5+, tvOS 18.4+, visionOS 2.4+, AirPlay audio SDK 2.7.1+, AirPlay video SDK 3.6.0.126+, CarPlay Communication Plug-in R18.1+).

## ☁️ Vulnérabilité Élevée dans AWS Amplify Studio (CVE-2025-4318)
Une vulnérabilité de validation d'entrée (CVSS non précisé, mais impact RCE suggère un score élevé) a été identifiée dans le composant UI d'AWS Amplify Studio, spécifiquement dans le package `amplify-codegen-ui` (versions <= 2.20.2). La faille permet à un utilisateur authentifié disposant des droits de créer ou modifier des composants d'exécuter du code JavaScript arbitraire lors du rendu et du processus de build du composant, car la fonction `expression-binding` ne valide pas correctement les propriétés du schéma de composant.

* Publication date : 2025/05/05
* 🗺️ Source : https://aws.amazon.com/security/security-bulletins/AWS-2025-010/
* 🐞 CVE : [CVE-2025-4318](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4318)
* 📦 CVE IMPACTED PRODUCT : AWS Amplify Studio amplify-codegen-ui (versions <= 2.20.2)
* ⚖️ CVSS : N/A (Implique un impact RCE pour utilisateur authentifié, probable sévérité Élevée)
* 🛡️ Security Recommandations : Mettre à niveau le package `aws-amplify/amplify-codegen-ui` vers la version 2.20.3 ou ultérieure. S'assurer que tout code forké ou dérivé intègre les correctifs de la nouvelle version.

## 🚪 Vulnérabilité Élevée dans Digigram PYKO-OUT (CVE-2025-3927)
Une vulnérabilité (CVSS non précisé, mais décrite comme "significative") a été identifiée dans les appareils Digigram PYKO-OUT AoIP (Audio-over-IP), classés comme End-of-Life (EOL). La faille réside dans la configuration par défaut du serveur web de l'appareil, qui ne requiert aucune authentification ni mot de passe. N'importe quel attaquant connaissant l'adresse IP de l'appareil (par défaut 192.168.0.100) peut accéder et manipuler sa configuration, contrôler les entrées/sorties audio, et potentiellement pivoter vers d'autres appareils connectés. Digigram ne fournira pas de correctif car le produit est EOL.

* Publication date : 2025/05/06
* 🗺️ Source : https://securityonline.info/digigram-pyko-out-aoip-devices-exposed-to-attacks-due-to-missing-default-password/
* 🐞 CVE : [CVE-2025-3927](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-3927)
* 📦 CVE IMPACTED PRODUCT : Digigram PYKO-OUT AoIP devices (produit End-of-Life)
* ⚖️ CVSS : N/A (Décrit comme "significatif", probable sévérité Élevée ou Critique)
* 🛡️ Security Recommandations : Modifier manuellement les paramètres de mot de passe dans l'interface web de l'appareil. Isoler les appareils PYKO-OUT sur un réseau séparé ou restreindre l'accès à leur interface web.
* 🚩 Indicator of Compromise :
    * IPv4 : 192[.]168[.]0[.]100 (adresse IP par défaut du serveur web)