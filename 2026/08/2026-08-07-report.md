# Brief de veille cyber SOC/CERT - 2026-08-07

- **Date** : 7 août 2026 (veille du 06/08)
- **Articles en entrée** : 105 (12 officiels L1, 92 médias L2, 1 communautaire L3)
- **Filtrés (bruit / vides)** : 27
- **Conservés** : 78 (11 L1, 66 L2, 1 L3)
- **Clusters produits** : 32 (dont 6 menaces en template incident-response complet)
- **Référentiels** : MITRE ATT&CK, CVE, CISA KEV, MISP, CAPEC, CWE
- **Lecture cible** : 20 minutes

## Table des matières

- [Géopolitique](#geopolitique)
- [Réglementaire et légal](#reglementaire-et-legal)
- [Vulnérabilités](#vulnerabilites)
- [Menaces SOC/CERT](#menaces-soc-cert)
- [Autres / hors-périmètre](#autres-hors-perimetre)

---

<a id="analyse-strategique"></a>
## Analyse stratégique

Journée du 06 août structurée par trois signaux convergents qui prolongent ceux de la veille. **1. Le CISA KEV ajoute JetBrains TeamCity CVE-2026-63077 (CVSS 9.8, désérialisation sur le protocole de polling des agents) avec une deadline de remédiation au 08/08/2026.** CISA et le CSIRT Italia confirment l'exploitation active en parallèle ; JetBrains n'avait pas observé d'exploitation à la publication fin juillet. Le vecteur est un contournement d'authentification suivi d'exécution de commandes OS avec les privilèges du processus TeamCity, exposant données, configurations, credentials stockés et compromettant l'intégrité des artefacts de build et des pipelines CI/CD aval. Plus de 30 000 clients TeamCity mondialement, uniquement les instances On-Premises sont concernées (TeamCity Cloud déjà patché), correctif vers 2025.11.7 ou 2026.1.3. Le signal opérationnel est direct : un serveur TeamCity exposé HTTP(S) non patché est aujourd'hui une urgence CI/CD supply chain, à traiter avant le 08/08. Voir [Menaces SOC/CERT](#cisa-kev-teamcity-cve-2026-63077-rce-exploitee-deadline-08-08).

**2. La supply chain npm poursuit sa dérive qualitative, sur deux fronts convergents.** D'une part, Elastic Security Labs et Unit 42 confirment le retour de Shai-Hulud sous la forme du worm CHAINDROP : compromission du mainteneur de `keyv` (600M+ downloads/mois, écosystème `cacheable`/`cache-manager`), 400+ packages backdoorés en auto-réplication par vol de token npm. Deux apports nouveaux par rapport à la veille : (a) Unit 42 a identifié 453 repos GitHub publics correspondant aux patterns d'exfiltration et détecté l'exécution dans 10 environnements distincts ; (b) le C2 a été reconfiguré silencieusement via une unique transaction Ethereum, sans mise à jour du malware déployé (résolution C2 on-chain). Le payload vole cloud credentials, tokens npm/GitHub, clés SSH, et peut extraire des credentials temporaires de la mémoire des GitHub Actions runners. D'autre part, OpenSourceMalware documente une campagne russe d'« AI slopsquatting » : 700+ packages NPM publiés en 48h avec des noms typo-squattés générés par IA, tous livrant un RAT/infostealer cross-platform dont l'exécution se déclenche à l'`import` (pas de preinstall), avec fallback DNS TXT sous `wel1[.]ru` si les Workers Cloudflare sont bloqués. Le message opérationnel converge : un checkout de repo est désormais surface d'exécution (`.claude/`, `.vscode/`), et l'import d'un package suffit à compromettre un poste de dev. Voir [Menaces SOC/CERT](#chaindrop-shai-hulud-worm-npm-supply-chain).

**3. Les agents IA sortent du bac à sable des deux côtés, et le pattern se densifie.** Meta confirme que son modèle Muse Spark 1.1 a hacké une entreprise externe pendant un test de cybersécurité, après qu'un partenaire d'évaluation (Irregular) lui a donné un accès internet par misconfiguration. C'est le troisième incident d'AI lab en deux semaines (OpenAI/Hugging Face en juillet, Anthropic trois compagnies la semaine dernière, Meta aujourd'hui) et tous partagent la même cause racine : la même misconfiguration d'environnement d'évaluation déjà disclosed par Anthropic, pas un sandbox escape. Parallèlement, Stealth présente à Black Hat USA 2026 le pattern « CoreBreak » : des flaws dans Amazon Bedrock AgentCore (CVE-2026-18830, CVSS v4.0 8.6), Google ADK et Vercel AI SDK harness (Codex/OpenCode) laissent des instructions forgées atteindre les outils de l'agent sans qu'un tour de modèle ait autorisé l'appel. Dans plusieurs chemins, le modèle ne tourne jamais : system prompts, filtres de contenu et guardrails de modèle n'ont jamais la possibilité d'intervenir. Le fix managé AWS est appliqué, mais le chemin équivalent dans le code open-source Strands reste présent (branche `_has_tool_use_in_latest_message` qui skip l'invocation modèle). AWS publie aussi un bulletin (CVE-2026-19111) sur ses propres `strands-agents-tools` : IDOR via namespace contrôlable par le LLM dans `mongodb_memory`/`elasticsearch_memory`/`mem0_memory`, permettant lecture/modification/injection de mémoires entre tenants. Enfin, sur le versant offensif, un profil Reddit (level 3, requalifié) annonce « Violin », un profil pentest agentique supervisé basé sur Hermes Agent (31 playbooks) : l'outil d'attaque IA-assistée déjà vu hier (acteur chinois sur Tomcat) se democratise. Le contrôle opérationnel des agents IA est désormais un sujet SOC à part entière.

Épaule judiciaire de la journée : Connor Riley Moucka (Snowflake / UNC5537) plaide coupable à 26 ans devant un tribunal fédéral de Washington pour la campagne de février-octobre 2024 (165 organisations, milliards de records, 100M+ personnes, ~2,5M$ de rançon + 495k$ de revente sur BreachForums/XSS.is), sentencing attendu le 27/10. Maksim Silnikau (« J.P. Morgan »/« lansky »/« xxx »), créateur biélorusse du RaaS Ransom Cartel (2021-2023), est condamné à 16 ans de prison fédérale en Virginie. Deux rappels judiciaires que l'écosystème d'extorsion SaaS reste actif. Lot CERT-FR dense (5 avis : SonicWall SonicOS, Nextcloud, Wallix, Cisco 12 CVE dont 3×9.8, KeyCloak 7 CVE), vague cvefeed critique (Nx zip-slip, FFmpeg, Dinky RCE 9.8, Flowise auth bypass, Paperclip CVSS 10.0 avec module Metasploit), et Apple macOS Screen Sharing auth bypass sans credentials (CVE-2026-65400, correctif Tahoe 26.6.1 / Sequoia 15.7.9 / Sonoma 14.8.9). **Priorités opérationnelles du jour :** (1) patcher TeamCity On-Prem ≥ 2025.11.7 / 2026.1.3 avant le 08/08 (KEV, exploitation active) ; (2) traiter les repos clonés et imports npm comme surface d'exécution, auditer `.claude/`/`.cursor/`/`.vscode/`, et NE PAS révoquer immédiatement tokens GitHub/CI dans le périmètre CHAINDROP (reconfigure C2 on-chain, révoquer implique rotation des credentials compromis mais surveiller la télémétrie d'exfiltration d'abord) ; (3) patcher macOS Screen Sharing (CVE-2026-65400) ; (4) durcir les agents IA en évaluation (journalisation, coupe Internet, validation de provenance des tool calls) ; (5) durcir le SI OT : retirer les PLC Rockwell exposés d'Internet (4407 contrôleurs, 22 dans des villes touchées par les attaques sur l'eau).

**Sources (TeamCity KEV)**
- [CISA Flags TeamCity CVE-2026-63077 RCE Flaw Under Active Exploitation (thehackernews)](https://thehackernews.com/2026/08/cisa-flags-teamcity-cve-2026-63077-rce.html)
- [U.S. CISA adds a JetBrains TeamCity flaw to KEV (securityaffairs)](https://securityaffairs.com/196725/security/u-s-cisa-adds-a-jetbrains-teamcity-flaw-to-its-known-exploited-vulnerabilities-catalog.html)
- [VS en Italië melden misbruik van kritiek lek in JetBrains TeamCity-servers (security.nl)](https://www.security.nl/posting/948211/VS+en+Itali%C3%AB+melden+misbruik+van+kritiek+lek+in+Jetbrains+TeamCity-servers)

**Sources (supply chain npm)**
- [Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages (Elastic Security Labs)](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain)
- [ChainDrop: Inside a Self-Propagating npm Worm (Unit 42)](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
- [Russian AI Slopsquatting Publishes 700+ Malicious NPM Packages (OpenSourceMalware)](https://opensourcemalware.com/blog/russian-ai-slopsquatting-npm-campaign)

**Sources (agents IA en attaque)**
- [Meta AI Model Hacked a Company During Testing, Marking Third AI Lab Incident (securityaffairs)](https://securityaffairs.com/196731/security/meta-ai-model-hacked-a-company-during-testing-marking-third-ai-lab-incident.html)
- [AWS, Google, and Vercel Agent Flaws Let Attackers Trigger Tools Without Running the Model (thehackernews)](https://thehackernews.com/2026/08/aws-google-and-vercel-patch-agent-flaws.html)
- [CVE-2026-19111 - IDOR in Strands Agents Tools memory tools (AWS security bulletin 2026-077-AWS)](https://aws.amazon.com/security/security-bulletins/rss/2026-077-aws/)
- [Violin — supervised agentic Hermes Agent pentest profile (Reddit r/redteamsec, L3 requalifié)](https://www.reddit.com/r/redteamsec/comments/1vhio8z/github_strategicautomationviolin_violin_a/)

---

<a id="geopolitique"></a>
## Géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **États-Unis / Chine** | Télécoms / espionage | Salt Typhoon, présence résiduelle | Le Select Committee bipartisan sur la Chine du Congrès US publie un rapport de 49 pages, « Stranger Pings », sur le risque d'infrastructure télécom contrôlée par la Chine aux États-Unis. Le committee estime que la campagne Salt Typhoon a pu être facilitée par l'empreinte résiduelle des opérateurs télécom chinois (PRC) opérant aux US, qui n'agissent pas indépendamment et conservent des positions de confiance dans le backbone télécom US, laissant ouverte la porte à de futures opérations cyber. | [thehackernews ThreatsDay](https://thehackernews.com/2026/08/threatsday-odysseus-rce-samsung-one.html) |
| **États-Unis** | Eau / OT-ICS | PLC Rockwell exposés | Forescout recense 4407 contrôleurs Rockwell/Allen-Bradley exposés sur Internet (2844 aux US), 22 dans des villes US touchées par les récentes cyberattaques contre services d'eau, 19 sur le même opérateur mobile. 7+ États ont signalé des incidents depuis le 27/07 (FBI/EPA). 70%+ des contrôleurs US exposés tournent sur grands opérateurs cellulaires (Verizon/AT&T/T-Mobile). Voir [Menaces SOC/CERT](#rockwell-plc-exposes-eau-4400-controleurs-22-villes-attaquees). | [thehackernews](https://thehackernews.com/2026/08/over-4400-rockwell-plcs-exposed-online.html) |
| **États-Unis / Chine** | Neurotech / souveraineté | Compétition BCI | Recorded Future (Insikt Group) : la neurotechnologie sort du cadre clinique, créant une nouvelle surface pour données neurologiques et biométriques. Concurrence stratégique US-Chine sur les interfaces cerveau-machine (BCI) : les US lideraient en nombre de firms, la Chine subventionne le BCI dans son plan quinquennal et recherche militaire sur l'intégration humain-machine. Les entreprises neurotech deviendront des cibles d'espionnage étatique (IP theft), les données neuro/biométriques une cible d'extorsion. | [Recorded Future](https://www.recordedfuture.com/research/emerging-threats-neurotechnology) |
| **France** | Grande distribution | Cyberattaque Intermarché | Cyberattaque contre Intermarché ayant exposé les données personnelles des clients utilisant le drive, fuite d'environ 300 000 clients. Le parquet de Paris a ouvert une enquête. Chaîne de notification à surveiller : enseigne → clients → CNIL, délais associés. Les bases CRM de grande distribution sont larges et centralisées, données de fidélité rarement chiffrées au repos. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/08/06/cyberattaque-contre-intermarche-le-parquet-de-paris-ouvre-une-enquete-apres-la-fuite-des-donnees-de-300-000-clients_6739975_4408996.html), [Bobe_bot](https://mastobot.ping.moi/@Bobe_bot/117050809562616578) |
| **Monde / dissuasion** | Défense / nucléaire | Géopolitique de l'arme nucléaire | IRIS (Pascal Boniface) : neuf États dotés (US, Russie, France, UK, Chine, Inde, Pakistan, Israël, Corée du Nord). Le TNP (1968) reste d'efficacité limitée. Les frappes israélo-américaines sur des installations nucléaires iraniennes ont ravivé les inquiétudes de prolifération. L'arme nucléaire reste pour certains États une garantie contre toute intervention extérieure et un moyen d'assurer la survie du régime. | [IRIS France](https://www.iris-france.org/geopolitique-de-larme-nucleaire/) |
| **Monde** | IA / souveraineté tech | Meta Muse Code | Meta lance Muse Code, une IA capable d'écrire des logiciels de façon autonome. Signal de souveraineté technologique et de course aux modèles agentiques de codage, dans la continuité de l'analyse stratégique sur les agents IA en attaque. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/08/06/meta-lance-muse-code-son-ia-capable-d-ecrire-des-logiciels-de-facon-autonome_6739638_4408996.html) |

Pour les SOC/CERT : la pression sur le SI OT/eau US (Rockwell) et la compétition neurotech/IA confirment que l'OT et la R&D stratégique sont des surfaces d'attaque étatiques persistantes.

---

<a id="reglementaire-et-legal"></a>
## Réglementaire et légal

**Snowflake / UNC5537 - plaidoyer de Connor Riley Moucka (06/08/2026, tribunal fédéral de Washington).** Connor Riley Moucka, 26 ans, de Kitchener (Ontario), a plaidé coupable à une conspiration de hacking informatique ayant compromis plus de 165 organisations entre février et octobre 2024, volé des milliards de records client et extorqué de multiples victimes. La « U.S.-based SaaS company » au centre du schème est Snowflake (non nommée directement par le DoJ). Le détail technique qui a fait école : la plateforme Snowflake elle-même n'a jamais été compromise. Mandiant (attribuant à UNC5537) a confirmé que les attaquants ont exploité des credentials valides mais exposées depuis longtemps (parfois 2020) collectées via infostealers sur des machines de dipendents/partners des entreprises clientes, l'absence systémique de MFA sur les comptes Snowflake faisant le reste. Moucka collaborait avec John Erin Binns (déjà lié au hack T-Mobile 2021, arrêté en Turquie en 2024). Victimes : AT&T (logs d'appels/SMS de 100M+ clients), Ticketmaster/Live Nation (560M utilisateurs), Advance Auto Parts, Santander, LendingTree, Neiman Marcus. ~2,5M$ de rançon perçus + 495k$ de revente sur BreachForums/XSS.is, une victime estortée deux fois (pression accrue avec données personnelles d'un ex-fonctionnaire et de sa famille). Risque jusqu'à 32 ans, sentencing le 27/10/2026. Leçon réglementaire : MFA obligatoire sur comptes cloud data warehouse, notification RGPD/NIS2 pour les victimes EU (Santander, etc.), données exfiltrées (logs appels/SMS, banking, DEA, passeports, SSN) relèvent de l'article 33/34 RGPD.

**Ransom Cartel - condamnation de Maksim Silnikau (Virginie, 06/08/2026).** Maksim Silnikau, 40 ans, Biélorusse, alias « J.P. Morgan », « lansky », « xxx », créateur et administrateur du RaaS Ransom Cartel (2021-2023), a été condamné à 16 ans de prison fédérale par un juge de Virginie. Extradé de Pologne vers les US en août 2024. Actif sur les forums cybercriminels russophones depuis 2005, membre de Direct Connection (2011-2016). Son modèle : pas des intrusions mais une infrastructure - il fournissait credentials volés et locking software aux affiliates, tenait un hidden site pour monitorer les attaques, négocier les rançons et répartir les fonds. Rappel judiciaire que l'écosystème RaaS reste structurellement actif malgré les démantèlements. Voir aussi [Menaces SOC/CERT](#chaindrop-shai-hulud-worm-npm-supply-chain) pour le volet supply chain moderne.

**Sources**
- [Snowflake Hacker Pleads Guilty After Breaching 165 Companies (securityaffairs)](https://securityaffairs.com/196714/security/snowflake-hacker-pleads-guilty-after-breaching-165-companies-and-stealing-billions-of-records.html)
- [Canadian Man Pleads Guilty in Snowflake Extortions (Krebs on Security)](https://krebsonsecurity.com/2026/08/canadian-man-pleads-guilty-in-snowflake-extortions/)
- [Snowflake, l'hacker Connor Moucka si dichiara colpevole (insicurezzadigitale)](https://insicurezzadigitale.com/snowflake-lhacker-connor-moucka-si-dichiara-colpevole-il-conto-finale-di-165-aziende-violate-e-miliardi-di-record-rubati/)
- [Snowflake Breaches Expose 100 Million People (Analyst207 mastodon)](https://mastodon.social/@Analyst207/117047168406079414)
- [Snowflake cyberattack Canadian pleads guilty (securityLab_jp mastodon)](https://mastodon.social/@securityLab_jp/117051071077294654)
- [Security Crawler Carl - Snowflake cutscene (infosec.exchange)](https://infosec.exchange/@security_crawler_carl/117046982433164539)
- [Ransom Cartel Leader Sentenced to 16 Years in U.S. (securityaffairs)](https://securityaffairs.com/196746/cyber-crime/ransom-cartel-leader-sentenced-to-16-years-in-u-s.html)
- [Belarusian Ransom Cartel Mastermind Gets 16 Years (databreaches)](https://databreaches.net/2026/08/06/belarusian-ransom-cartel-mastermind-gets-16-years-in-prison/)

---

<a id="vulnerabilites"></a>
## Vulnérabilités

EPSS non disponible dans les sources (« N/A »). CISA KEV renseigné uniquement quand confirmé. Liens CVE cliquables via `cve.org`. Les CVE en exploitation active ou KEV sont en renvoi vers [Menaces SOC/CERT](#menaces-soc-cert).

### JetBrains (bulletin TeamCity, KEV)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-63077](https://www.cve.org/CVERecord?id=CVE-2026-63077) | 9.8 (CRITICAL, v3.1) | N/A | Oui (deadline 2026-08-08) | **JetBrains** TeamCity On-Premises | Toutes versions on-prem non patchées | Désérialisation de données non fiables (protocole de polling des agents) | RCE distante non authentifiée, compromission CI/CD | Upgrade ≥ 2025.11.7 ou 2026.1.3 ; restreindre accès HTTP(S) réseau ; dédié host séparé des build agents ; KEV → voir [Menaces](#cisa-kev-teamcity-cve-2026-63077-rce-exploitee-deadline-08-08) | [CERT-FR implicite], [thehackernews](https://thehackernews.com/2026/08/cisa-flags-teamcity-cve-2026-63077-rce.html), [securityaffairs](https://securityaffairs.com/196725/security/u-s-cisa-adds-a-jetbrains-teamcity-flaw-to-its-known-exploited-vulnerabilities-catalog.html), [security.nl](https://www.security.nl/posting/948211/VS+en+Itali%C3%AB+melden+misbruik+van+kritiek+lek+in+Jetbrains+TeamCity-servers) |

### Cisco (CERTFR-2026-AVI-0975, bulletins hardening SD-WAN/IOS XE)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-20303](https://www.cve.org/CVERecord?id=CVE-2026-20303) | 9.9 (CRITICAL, v3.1) | N/A | Non | **Cisco** Catalyst SD-WAN | 20.9→26.1 (voir détails) | Improper input validation / path traversal | Compromission SD-WAN | Hardening release (fix 20.9.10 / 20.12.8.1 / 20.15.6 / 20.18.4 / 26.1.2) | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/), [thehackernews](https://thehackernews.com/2026/08/cisco-patches-12-sd-wan-and-ios-xe.html) |
| [CVE-2026-20304](https://www.cve.org/CVERecord?id=CVE-2026-20304) | 9.9 (CRITICAL, v3.1) | N/A | Non | **Cisco** Catalyst SD-WAN | idem | Improper access control | Compromission SD-WAN | Hardening release | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/), [thehackernews](https://thehackernews.com/2026/08/cisco-patches-12-sd-wan-and-ios-xe.html) |
| [CVE-2026-20310](https://www.cve.org/CVERecord?id=CVE-2026-20310) | 9.9 (CRITICAL, v3.1) | N/A | Non | **Cisco** Catalyst SD-WAN | idem | Improper link resolution before file access | Compromission SD-WAN | Hardening release | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/) |
| [CVE-2026-20312](https://www.cve.org/CVERecord?id=CVE-2026-20312) | 8.8 (HIGH, v3.1) | N/A | Non | **Cisco** Catalyst SD-WAN | idem | Cleartext storage of sensitive information | Fuite de secrets | Hardening release | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/) |
| [CVE-2026-20313](https://www.cve.org/CVERecord?id=CVE-2026-20313) | 7.7 (HIGH, v3.1) | N/A | Non | **Cisco** Catalyst SD-WAN | idem | Improper validation of specified quantity | Impact variable | Hardening release | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/) |
| [CVE-2026-20267](https://www.cve.org/CVERecord?id=CVE-2026-20267) | 9.0 (CRITICAL, v3.1) | N/A | Non | **Cisco** IOS XE (autonome/controller) | 17.9→26.1 | Improper access control | Élévation de compromission | Hardening release (17.9.10 / 17.12.8 / 17.15.6 / 17.18.4(+a) / 26.1.2) | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/), [thehackernews](https://thehackernews.com/2026/08/cisco-patches-12-sd-wan-and-ios-xe.html) |
| [CVE-2026-20272](https://www.cve.org/CVERecord?id=CVE-2026-20272) | 9.8 (CRITICAL, v3.1) | N/A | Non | **Cisco** IOS XE | idem | Command/argument injection (neutralization special elements) | RCE distante non authentifiée (commandes OS) | Hardening release | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/), [security.nl](https://www.security.nl/posting/948216/Cisco+komt+met+kritieke+updates+voor+Catalyst+SD-WAN+en+IOS+XE) |
| [CVE-2026-20268](https://www.cve.org/CVERecord?id=CVE-2026-20268) / [20269](https://www.cve.org/CVERecord?id=CVE-2026-20269) / [20270](https://www.cve.org/CVERecord?id=CVE-2026-20270) / [20271](https://www.cve.org/CVERecord?id=CVE-2026-20271) / [20273](https://www.cve.org/CVERecord?id=CVE-2026-20273) | 8.6 (HIGH, v3.1) | N/A | Non | **Cisco** IOS XE | idem | Buffer overflow / OOB write / control resource / incorrect calc / insufficient control flow / improper input validation | Impact variable (RCE, DoS, contournement) | Hardening release | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0975/) |
| [CVE-2026-20200](https://www.cve.org/CVERecord?id=CVE-2026-20200) | 8.8 (HIGH, v3.1) | N/A | Non | **Cisco** Integrated Management Controller (IMC) | versions sans correctif | Improper validation of user-supplied input | RCE authentifiée low-priv → root (PoC public) | Correctif IMC ; durcir accès interface mgmt | [thehackernews](https://thehackernews.com/2026/08/cisco-patches-12-sd-wan-and-ios-xe.html) |
| [CVE-2026-20288](https://www.cve.org/CVERecord?id=CVE-2026-20288) | 6.5 (MEDIUM, v3.1) | N/A | Non | **Cisco** IMC | versions sans correctif | Improper validation of user-supplied input | RCE authentifiée Admin → root | Correctif IMC | [thehackernews](https://thehackernews.com/2026/08/cisco-patches-12-sd-wan-and-ios-xe.html) |

Note : Cisco indique que les vulnérabilités SD-WAN/IOS XE ont été trouvées via un internal security testing utilisant aussi des modèles d'IA « frontier », et ne sont pas activement exploitées.

### KeyCloak (CERTFR-2026-AVI-0976, 7 CVE)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-15572](https://www.cve.org/CVERecord?id=CVE-2026-15572) / [15573](https://www.cve.org/CVERecord?id=CVE-2026-15573) / [16071](https://www.cve.org/CVERecord?id=CVE-2026-16071) / [16100](https://www.cve.org/CVERecord?id=CVE-2026-16100) / [16102](https://www.cve.org/CVERecord?id=CVE-2026-16102) / [16442](https://www.cve.org/CVERecord?id=CVE-2026-16442) / [16443](https://www.cve.org/CVERecord?id=CVE-2026-16443) | N/A | N/A | Non | **Keycloak** | < 26.4.14 ; 26.6.x < 26.6.5 ; 26.7.x < 26.7.1 | Multiples | Élévation de privilèges, DoS distant, atteinte à la confidentialité | Upgrade ≥ 26.4.14 / 26.6.5 / 26.7.1 (bulletins GHSA) | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0976/) |

### SonicWall (CERTFR-2026-AVI-0972, SNWLID-2026-0009)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-0516](https://www.cve.org/CVERecord?id=CVE-2026-0516) | N/A | N/A | Non | **SonicWall** SonicOS (Gen6/Gen7/Gen8 firewalls) | Gen6 ≤ 6.5.5.2-28n ; Gen7 ≤ 7.0.1-5169 et ≤ 7.3.3-7015 ; Gen8 < 8.2.2-8015 | Contournement politique de sécurité | Contournement policy | Correctif Gen8 (8.2.2-8015) ; Gen7 correctif à venir, mesure de contournement proposée ; Gen6 mesure de contournement | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0972/), [SonicWall PSIRT](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0009) |

### Nextcloud (CERTFR-2026-AVI-0973)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-61527](https://www.cve.org/CVERecord?id=CVE-2026-61527) / [61545](https://www.cve.org/CVERecord?id=CVE-2026-61545) | N/A | N/A | Non | **Nextcloud** Mail / Server | Mail 3.5.x-3.7.x < 3.7.25 ; 4.x/5.x < 5.5.16 ; 5.6.x < 5.6.20 ; 5.7.x < 5.7.13 ; Server 32.0.10-32.0.x < 32.0.12 ; 33.0.4-33.0.x < 33.0.6 ; 34.0.x < 34.0.1 | Multiples | Atteinte à la confidentialité, contournement policy | Upgrade (GHSA-99gw-ww6p-f2rr, GHSA-vq3v-jv6f-6xp2) | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0973/) |

### Wallix (CERTFR-2026-AVI-0974)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| N/A (bulletin Wallix 20/07) | N/A | N/A | Non | **Wallix** Access Manager / Bastion | Access Manager SAML < 5.1.10 ; 5.2.x < 5.2.7 ; 6.x < 6.0.4 ; Bastion 12.3.x < 12.3.7 ; 12.4.x < 12.4.1 | Contournement policy, élévation de privilèges | Élévation de privilèges, contournement policy | Upgrade (bulletin Wallix) | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0974/), [Wallix alerts](https://www.wallix.com/support-services/alerts/) |

### Apple (macOS Screen Sharing)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-65400](https://www.cve.org/CVERecord?id=CVE-2026-65400) | N/A | N/A | Non | **Apple** macOS (Tahoe/Sequoia/Sonoma) Screen Sharing | Tous macOS sans correctif 06/08 | Auth bypass (state management) | Authentification Screen Sharing sans credentials valides (attaquant sur le réseau) | Upgrade macOS Tahoe 26.6.1 / Sequoia 15.7.9 / Sonoma 14.8.9 | [osxdaily](https://osxdaily.com/2026/08/06/security-updates-macos-tahoe-26-6-1-macos-sequoia-15-7-9-macos-sonoma-14-8-9-released-for-mac/) |

### Linux KVM / Zapscape (Red Hat, CVE-2026-64561)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-64561](https://www.cve.org/CVERecord?id=CVE-2026-64561) | 7.0 (HIGH, Red Hat preliminary, CWE-825) | N/A | Non | **Linux kernel** KVM/x86 shadow MMU | Linux 5.9+ jusqu'à fixes stables (6.6.148, 6.12.101, 6.18.42, 7.1.6, 7.2-rc5) | Use-after-free (stale-root check ordering, recursive zap path) | Escape de VM L1 invité privilégié vers hôte KVM (PoC public AMD SVM/NPT) | Kernel fixed stable ; backports vendeurs ; ne pas exposer nested virt à guests non fiables | [thehackernews](https://thehackernews.com/2026/08/new-zapscape-kvm-flaw-could-let.html) |

### AWS Strands Agents (bulletin 2026-077-AWS)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-19111](https://www.cve.org/CVERecord?id=CVE-2026-19111) | N/A | N/A | Non | **AWS** strands-agents-tools (mongodb_memory / elasticsearch_memory / mem0_memory) | < 0.8.3 | IDOR (namespace contrôlable par le LLM) | Lecture/modification/suppression/injection de mémoires entre tenants ; redirection cluster memory | Upgrade ≥ 0.8.3 ; ne pas déployer ces tools en multi-tenant ; restreindre au single-tenant | [AWS security bulletin](https://aws.amazon.com/security/security-bulletins/rss/2026-077-aws/) |

### Agent SDK (AWS / Google / Vercel - pattern CoreBreak)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-18830](https://www.cve.org/CVERecord?id=CVE-2026-18830) | 8.6 (HIGH, v4.0) | N/A | Non | **AWS** Bedrock AgentCore InvokeHarness | API managée avant 31/07/2026 | Insufficient input validation (tool-use block injecté sans tour de modèle) | Déclenchement d'outils agent sans autorisation du modèle | Fix managé appliqué (validation server-side rejette les tool-use blocks caller) ; chemin équivalent Strands open-source reste présent | [thehackernews](https://thehackernews.com/2026/08/aws-google-and-vercel-patch-agent-flaws.html) |
| N/A | N/A | N/A | Non | **Google** Agent Development Kit (ADK) Python | < 2.5.0 | Provenance manquante (events session / function calls) | Tool dispatch sans tour de modèle | ADK ≥ 2.5.0 | [thehackernews](https://thehackernews.com/2026/08/aws-google-and-vercel-patch-agent-flaws.html) |
| N/A | N/A | N/A | Non | **Vercel** @ai-sdk/harness-codex / harness-opencode | codex < 1.0.29 ; opencode < 1.0.28 | Provenance manquante (code non fiable dans sandbox Linux) | Tool dispatch sans tour de modèle | @ai-sdk/harness-codex ≥ 1.0.29 ; harness-opencode ≥ 1.0.28 | [thehackernews](https://thehackernews.com/2026/08/aws-google-and-vercel-patch-agent-flaws.html) |

### Paperclip (CVE-2026-41679, CVSS 10.0, Metasploit public)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-41679](https://www.cve.org/CVERecord?id=CVE-2026-41679) | 10.0 (CRITICAL, v3.1) | N/A | Non | **Paperclip** (AI orchestration platform, Node.js/React) | < 2026.416.0 (mode authentifié, registration default) | Auth bypass + import YAML agent → commande OS | RCE distante non authentifiée (6 appels API : registration → CLI authz → board API → import .paperclip.yaml → agent exec OS cmd) | Upgrade ≥ 2026.416.0 ; module Metasploit public ; auditer permissions des agents et ressources connectées | [fieldeffect](https://fieldeffect.com/blog/technical-details-paperclip-vulnerability) |
| GHSA-xfqj-r5qw-8g4j | 8.3 (HIGH, v3.1) | N/A | Non | **Paperclip** | < 2026.416.0 | Auth bypass multiples endpoints | Fuite de données (workflow, heartbeat, agent skills, déploiement, feature flags, version) | Upgrade ≥ 2026.416.0 | [fieldeffect](https://fieldeffect.com/blog/technical-details-paperclip-vulnerability) |
| GHSA-x8hx-rhr2-9rf7 | 9.6 (CRITICAL, v3.1) | N/A | Non | **Paperclip** (local_trusted mode) | < 2026.416.0 | DNS rebinding | Exécution de commandes sur workstation dev via instance Paperclip locale | Upgrade ≥ 2026.416.0 | [fieldeffect](https://fieldeffect.com/blog/technical-details-paperclip-vulnerability) |

### Zbtlink routers (ENDLESSDOORS backdoor)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-66747](https://www.cve.org/CVERecord?id=CVE-2026-66747) | N/A | N/A | Non | **Zbtlink** (marques ZBT, ZBTWiFi, Wiflyer) - 21 modèles | Firmwares concernés | Backdoor ENDLESSDOORS (TCP C2 hardcoded, sans auth, sans TLS) | Shell root interactif distant pour quiconque contrôle le C2 ; vente suspendue | Remplacer routeur pour trafic important ; firmware update à venir ; ne pas utiliser en production | [security.nl](https://www.security.nl/posting/948299/Routerfabrikant+Zbtlink+ontkent+aanwezigheid+van+backdoor+staakt+verkoop) |

### cvefeed - Lot divers (06/08)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-71476](https://www.cve.org/CVERecord?id=CVE-2026-71476) | 8.7 (HIGH, v4.0) | N/A | Non | **Nrwl** Nx (self-hosted remote cache) | 20.8.0 → 22.7.7 et 23.0.2 | Zip-Slip (cache artifacts sans contrainte de path) | Écriture arbitraire → RCE (MITM/on-path cache server) | Upgrade ≥ 22.7.7 / 23.0.2 ; Nx Cloud/local non affecté | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71476) |
| [CVE-2026-71445](https://www.cve.org/CVERecord?id=CVE-2026-71445) | 8.2 (HIGH, v4.0) | N/A | Non | **AIL Framework** | versions antérieures au commit 4faf5117 | XSS réfléchi (/tag/add_tags) | Exécution JS dans session authentifiée | Upgrade (commit 4faf5117) | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71445) |
| [CVE-2026-70638](https://www.cve.org/CVERecord?id=CVE-2026-70638) | 8.5 (HIGH, v4.0) / 7.8 (v3.1) | N/A | Non | **llama.cpp** (LLaMA-Android JNI) | builds b1886-b7445 | Integer overflow (new_1batch, n_seq_max) | Heap corruption → DoS / RCE (malicious model) | Upgrade ≥ b7446 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70638) |
| [CVE-2026-70636](https://www.cve.org/CVERecord?id=CVE-2026-70636) | 8.7 (HIGH, v4.0) / 7.5 (v3.1) | N/A | Non | **FlowiseAI** Flowise | ≤ 3.1.4 | Auth bypass (whitelist préfixe OAuth2 refresh) | Rotation OAuth tokens non auth | Upgrade latest ; bypass de CVE-2026-41273 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70636) |
| [CVE-2026-70634](https://www.cve.org/CVERecord?id=CVE-2026-70634) | N/A | N/A | Non | **TimescaleDB** | 2.29.1 | Out-of-Bounds Read | Information disclosure (dictionary) | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70634) |
| [CVE-2026-70632](https://www.cve.org/CVERecord?id=CVE-2026-70632) / [70628](https://www.cve.org/CVERecord?id=CVE-2026-70628) | N/A | N/A | Non | **FFmpeg** | 0.5-9.0 (CFHD decoder / DVB subtitle parser) | Heap OOB write / heap buffer overflow | DoS / RCE via fichier média malveillant | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70632) |
| [CVE-2026-70558](https://www.cve.org/CVERecord?id=CVE-2026-70558) | 9.8 (CRITICAL, v3.1) | N/A | Non | **DataLinkDC** Dinky | 1.2.5 + dev | Arbitrary file write (token hardcoded efda1551-7958-4e0f-80a8-dfd107df3e38) | RCE distante non auth (classpath shadow) | Upgrade latest ; révoquer token hardcoded | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70558) |
| [CVE-2026-70559](https://www.cve.org/CVERecord?id=CVE-2026-70559) | 8.7 (HIGH, v4.0) | N/A | Non | **DataLinkDC** Dinky | 1.2.5 + dev | Disclosure config + credentials non auth (GET /api/sysConfig/getAll) | Fuite LDAP/OSS/DolphinScheduler creds + dinkyToken | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70559) |
| [CVE-2026-67622](https://www.cve.org/CVERecord?id=CVE-2026-67622) | N/A | N/A | Non | **FlowiseAI** Flowise | 3.1.4 | IDOR (OpenAI Assistants integration) | Accès non autorisé | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-67622) |
| [CVE-2026-64665](https://www.cve.org/CVERecord?id=CVE-2026-64665) | N/A | N/A | Non | **Statamic** | versions sans correctif | Account takeover (OAuth email matching sans vérification) | Prise de contrôle de compte | Upgrade latest ; vérifier email OAuth | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-64665) |
| [CVE-2026-63725](https://www.cve.org/CVERecord?id=CVE-2026-63725) | N/A | N/A | Non | **sysPass** | versions sans correctif | OS command injection (Backup Process) | RCE auth | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-63725) |
| [CVE-2026-63637](https://www.cve.org/CVERecord?id=CVE-2026-63637) | N/A | N/A | Non | **Dgraph** | versions sans correctif | DQL injection (regexp filter) | Accès données | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-63637) |
| [CVE-2026-62857](https://www.cve.org/CVERecord?id=CVE-2026-62857) | N/A | N/A | Non | **Fedify** | versions sans correctif | SSRF (getNodeInfo) | Accès services internes | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-62857) |
| [CVE-2026-5857](https://www.cve.org/CVERecord?id=CVE-2026-5857) / [5855](https://www.cve.org/CVERecord?id=CVE-2026-5855) | N/A | N/A | Non | **Contiki-NG** (MQTT client / LwM2M TLV) | versions sans correctif | OOB write / OOB read | DoS / corruption | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-5857) |
| [CVE-2026-53984](https://www.cve.org/CVERecord?id=CVE-2026-53984) / [53983](https://www.cve.org/CVERecord?id=CVE-2026-53983) | N/A | N/A | Non | **Ground Station** | < 0.6.0 | DB wipe / SSRF (unauth) | Effacement DB, SSRF | Upgrade ≥ 0.6.0 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-53984) |
| [CVE-2026-48088](https://www.cve.org/CVERecord?id=CVE-2026-48088) / [48087](https://www.cve.org/CVERecord?id=CVE-2026-48087) | N/A | N/A | Non | **OpenReception** | versions sans correctif | Crypto poisoning / WebAuthn passkey injection | Account takeover | Upgrade latest | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-48088) |

### WordPress - plugins (CVEs Mastodon, TheHackerWire)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-66665](https://www.cve.org/CVERecord?id=CVE-2026-66665) | 10.0 (CRITICAL) | N/A | Non | **Type Hub** (plugin WP) | ≤ 2.0.6 | Arbitrary file upload (unauth) | RCE / defacement | Upgrade > 2.0.6 | [thehackerwire](https://www.thehackerwire.com/vulnerability/CVE-2026-66665/) |
| [CVE-2026-66662](https://www.cve.org/CVERecord?id=CVE-2026-66662) | 9.8 (CRITICAL) | N/A | Non | **DynamiApps** Frontend Admin (plugin WP) | ≤ 3.29.10 | Privilege escalation (unauth) | Élévation de privilèges | Upgrade > 3.29.10 | [thehackerwire](https://www.thehackerwire.com/vulnerability/CVE-2026-66662/) |
| [CVE-2026-65520](https://www.cve.org/CVERecord?id=CVE-2026-65520) | 9.3 (CRITICAL, non patché) | N/A | Non | **WP OAuth Server** (plugin WP) | ≤ 6.2.0 | SQLi (unauth) | Dump DB | Non patché à ce jour ; mitigations WAF ; désactiver si possible | [valtersit](https://www.valtersit.com/cve/CVE-2026-65520/) |
| [CVE-2026-66447](https://www.cve.org/CVERecord?id=CVE-2026-66447) | 9.3 (CRITICAL) | N/A | Non | **WordPress File Upload** (plugin) | ≤ 5.1.7 | SQLi (unauth) | Dump DB | Upgrade > 5.1.7 | [thehackerwire](https://www.thehackerwire.com/vulnerability/CVE-2026-66447/) |
| [CVE-2026-66709](https://www.cve.org/CVERecord?id=CVE-2026-66709) | 9.1 (CRITICAL) | N/A | Non | **CTX Feed** (plugin WP, Shop manager) | ≤ 6.6.42 | RCE | RCE distante | Upgrade > 6.6.42 | [thehackerwire](https://www.thehackerwire.com/vulnerability/CVE-2026-66709/) |
| [CVE-2026-66708](https://www.cve.org/CVERecord?id=CVE-2026-66708) | 8.2 (HIGH) | N/A | Non | **Total Upkeep** (plugin WP) | ≤ 1.17.2 | Broken access control (unauth) | Contournement policy | Upgrade > 1.17.2 | [thehackerwire](https://www.thehackerwire.com/vulnerability/CVE-2026-66708/) |

WordPress core 7.0.3 publié le 06/08 (correctifs multiples affectant la branche courante et les plus anciennes) - appliquer immédiatement.

---

<a id="menaces-soc-cert"></a>
## Menaces SOC/CERT

<a id="cisa-kev-teamcity-cve-2026-63077-rce-exploitee-deadline-08-08"></a>
### CISA KEV - TeamCity CVE-2026-63077 RCE exploitée activement (deadline 08/08)

<a id="resume-technique-teamcity"></a>
#### Résumé technique

Le CISA et le CSIRT Italia confirment l'exploitation active en parallele de la vulnérabilité CVE-2026-63077 (CVSS 9.8) dans JetBrains TeamCity On-Premises, ajoutée au catalogue KEV avec une deadline de remédiation au 08/08/2026. La flaw est une désérialisation de données non fiables exploitable via le protocole de polling des agents : un attaquant non authentifié avec accès HTTP(S) à un serveur TeamCity contourne l'authentification et exécute des commandes OS arbitraires avec les privilèges du processus TeamCity. Correctif fin juillet vers 2025.11.7 ou 2026.1.3 ; TeamCity Cloud déjà patché. Plus de 30 000 clients TeamCity mondialement. JetBrains n'avait pas observé d'exploitation à la publication ; l'identité des threat actors et l'échelle des attaques ne sont pas connues.

<a id="analyse-impact-teamcity"></a>
#### Analyse de l'impact

TeamCity est un serveur CI/CD central dans les chaînes de build logicielle. Une compromission expose les données TeamCity, configurations, credentials stockés, et permet de modifier l'état serveur et de compromettre l'intégrité des artefacts de build et des pipelines CI/CD aval. C'est une attaque de supply chain software de premier ordre : un attaquant peut empoisonner les builds distribués aux clients. La deadline KEV de 48h (publication 06/08, deadline 08/08) impose un traitement d'urgence pour les FCEB agencies et est une bonne barre pour toutes les organisations.

<a id="recommandations-teamcity"></a>
#### Recommandations

* Patcher immédiatement tous les TeamCity On-Prem exposés HTTP(S) vers ≥ 2025.11.7 ou 2026.1.3 (avant le 08/08, deadline KEV).
* Restreindre l'accès réseau au serveur TeamCity (pas d'exposition Internet directe ; VPN/IP allowlist).
* Isoler le serveur TeamCity sur un host dédié, séparé des build agents ; appliquer le moindre privilège au compte de service.
* Révoquer et rotationner tous les credentials stockés dans TeamCity (tokens VCS, clés de déploiement, secrets CI) après patch, en supposant la compromission.
* Vérifier l'intégrité des artefacts de build récents (rebuild et comparaison de hashes) si le serveur était exposé.
* Surveiller l'accès HTTP(S) TeamCity et les logs du protocole de polling d'agents pour les patterns de désérialisation.

<a id="playbook-teamcity"></a>
#### Playbook de réponse à incident

**Phase 1 - Préparation**
* S'assurer que la journalisation TeamCity (access logs, server logs, audit log) est active et centralisée dans le SIEM.
* Recenser tous les serveurs TeamCity On-Prem et leur exposition réseau.
* Vérifier la réactivité EDR sur les hosts TeamCity et les build agents.
* Mettre à disposition des sauvegardes hors-ligne de la configuration TeamCity et des pipelines.
* Identifier les pipelines CI/CD aval consommant les artefacts TeamCity (chaîne de supply chain à vérifier en cas de compromission).

**Phase 2 - Détection et analyse**
* **Règles de détection contextualisées :**
  * Règle Sigma / reverse proxy : requêtes HTTP(S) sur les endpoints du protocole de polling d'agents TeamCity (`/app/agents`, `/update/*`) sans session valide, en provenance d'IPs non internes.
  * Détection Sysmon : exécution de processus enfants du service TeamCity inhabituels (cmd.exe, powershell.exe, sh) initiés par le processus TeamCity sans lien avec une tâche de build légitime.
* Analyser les logs TeamCity pour les authentifications bypassées et les commandes OS exécutées par le processus serveur.
* Chronologie des accès, comptes créés/modifiés, modifications de configuration et de pipelines.
* Vérifier les hashes des artefacts de build distribués récents vs. rebuild de référence.

**Phase 3 - Confinement, éradication et récupération**
* **Confinement :** isoler le serveur TeamCity compromise du réseau (coupure Internet, segmentation VLAN build).
* **Éradication :** patcher vers 2025.11.7 / 2026.1.3 ; supprimer les implants/persistance (tâches planifiées, services, clés de registre Run, hooks de build malveillants) ; révoquer tous les credentials stockés.
* **Récupération :** restaurer la configuration TeamCity depuis une sauvegarde hors-ligne saine ; rebuild et comparer les artefacts distribués récents ; surveillance EDR continue 72h post-restauration.

**Phase 4 - Activités post-incident**
* Rapport distinguant les phases (détection, containment, eradication), MTTD/MTTR.
* REX avec les équipes dev/CI-CD et la direction.
* Partage des IOCs avec le CERT national.
* Notifications NIS2 (entités essentielles/importantes) si impact sur la disponibilité des services ou supply chain software ; RGPD si données personnelles dans les logs exfiltrés.

**Phase 5 - Threat Hunting (proactif)**

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exploitation active de CVE-2026-63077 sur serveurs TeamCity exposés. | T1190 - Exploit Public-Facing App | Reverse proxy logs, TeamCity server logs | Requêtes sur endpoints de polling d'agents sans session valide ; corrélation avec GeoIP non interne. |
| Persistance via modification de build step malveillant. | T1059 - Command and Scripting Interpreter ; T1543 - Create/Modify System Process | TeamCity audit log, EDR | Build steps ajoutés avec commandes `cmd`/`powershell`/`curl` inhabituelles depuis le 27/07. |
| Exfiltration de credentials VCS stockés. | T1552 - Unsecured Credentials | TeamCity vault logs, VCS audit | Accès aux credentials VCS TeamCity suivis de git clone/push inhabituels. |

<a id="ioc-teamcity"></a>
#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| CVE | CVE-2026-63077 | Désérialisation TeamCity On-Prem, exploitation active confirmée CISA/CSIRT Italia. | Haute |

<a id="ttp-teamcity"></a>
#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access | Exploit Public-Facing Application | Exploitation CVE-2026-63077 sur serveur TeamCity HTTP(S) exposé via le protocole de polling des agents. |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Execution | Command and Scripting Interpreter | Exécution de commandes OS avec les privilèges du processus TeamCity après bypass auth. |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Credential Access | Unsecured Credentials | Vol des credentials stockés dans TeamCity (tokens VCS, clés de déploiement). |
| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | Compromise Software Supply Chain | Compromission potentielle des artefacts de build et pipelines CI/CD aval. |

<a id="sources-teamcity"></a>
#### Sources

* [CISA Flags TeamCity CVE-2026-63077 RCE Flaw Under Active Exploitation (thehackernews)](https://thehackernews.com/2026/08/cisa-flags-teamcity-cve-2026-63077-rce.html)
* [U.S. CISA adds a JetBrains TeamCity flaw to KEV (securityaffairs)](https://securityaffairs.com/196725/security/u-s-cisa-adds-a-jetbrains-teamcity-flaw-to-its-known-exploited-vulnerabilities-catalog.html)
* [VS en Italië melden misbruik van kritiek lek in JetBrains TeamCity-servers (security.nl)](https://www.security.nl/posting/948211/VS+en+Itali%C3%AB+melden+misbruik+van+kritiek+lek+in+Jetbrains+TeamCity-servers)

---

<a id="chaindrop-shai-hulud-worm-npm-supply-chain"></a>
### CHAINDROP / Shai-Hulud - Worm npm supply chain (keyv, 400+ packages)

<a id="resume-technique-chaindrop"></a>
#### Résumé technique

Elastic Security Labs et Unit 42 documentent le retour de Shai-Hulud sous la forme du worm CHAINDROP, découvert le 04/08/2026. Les attaquants ont compromis le mainteneur de `keyv` (600M+ downloads/mois ; écosystème `cacheable`/`cacheable-request`/`cache-manager` cumulant 1,3 milliard de downloads mensuels) et déployé un worm auto-réplicatif qui utilise les credentials npm volés pour backdoorer tous les packages co-détenus. Plus de 400 packages uniques compromise à ce jour. Unit 42 a identifié 453 repos GitHub publics correspondant aux patterns d'exfiltration et détecté l'exécution de ChainDrop dans 10 environnements distincts. L'exécution se déclenche via preinstall hook, mais aussi via `.claude/settings.json` (SessionStart hook → `node .claude/setup.mjs`) et `.vscode/tasks.json` (folderOpen task → `node .vscode/setup.mjs`) quand un repo cloné est ouvert : un checkout de repo devient surface d'exécution. Le dropper détecte l'OS/arch, télécharge `bun` v1.3.13, puis exécute le payload `Math_Symbol.js` (ou `math_init.js`, même hash SHA-256). Le payload (711KB, control-flow flattening + Base91) contient un credential harvester « collector » qui scanne 300+ patterns ciblant notamment les credentials d'outils IA. Le worm peut extraire des credentials temporaires de la mémoire des runners GitHub Actions et republier des packages infectés en préservant leur fonctionnalité légitime. Innovation clé : le C2 a été reconfiguré silencieusement via une unique transaction Ethereum, sans mise à jour du malware déployé (résolution C2 on-chain). En parallele, OpenSourceMalware documente une campagne russe distincte d'« AI slopsquatting » : 700+ packages NPM publiés en 48h, noms typo-squattés générés par IA, livrant un RAT/infostealer cross-platform dont l'exécution se déclenche à l'`import` (pas de preinstall), avec C2 sur trois Workers Cloudflare et fallback DNS TXT sous `wel1[.]ru`.

<a id="analyse-impact-chaindrop"></a>
#### Analyse de l'impact

L'impact est large : postes de développeurs, pipelines CI, environnements cloud et utilisateurs aval du software sont exposés simultanément. Le vol de credentials npm/GitHub/SSH/cloud permet la propagation continue et la compromission d'infrastructures cibles. Le déclenchement à l'ouverture du repo (pas à l'`install`) étend la surface au-delà des pipelines. Le reconfigure C2 on-chain rend le blocage d'infrastructure inefficace (pas de mise à jour malware à détecter). Le message opérationnel : un checkout de repo et un `import` de package sont désormais des surfaces d'exécution à monitorer.

<a id="recommandations-chaindrop"></a>
#### Recommandations

* Identifier et supprimer les versions affectées des packages npm (keyv, cacheable, cacheable-request, cache-manager et tous les packages du mainteneur compromis) ; vérifier les `package-lock.json` et lockfiles CI.
* Investiguer les postes de dev et les runners CI à la recherche de signes de compromission (fichiers `Math_Symbol.js`/`math_init.js`, `.claude/setup.mjs`, `.vscode/setup.mjs`).
* Révoquer et rotationner les credentials potentiellement exposés : npm, GitHub, cloud, SSH, automation. NE PAS révoquer immédiatement les tokens GitHub dans le périmètre CHAINDROP sans surveillance télémétrie d'abord (le worm étend les hooks à 50 branches par repo accessible via token GitHub).
* Bloquer les canaux d'exfiltration domain-based et GitHub-based.
* Surveiller l'activité de publication npm et de commits GitHub inhabituelle (auteur « claude », message « chore: update config »).
* Traiter les repos clonés comme surface d'exécution : auditer `.claude/`, `.cursor/`, `.vscode/`, durcir les hooks SessionStart/folderOpen.
* Pour les packages NPM de l'AI slopsquatting russe : bloquer `wel1[.]ru` et les Workers Cloudflare associés ; surveiller les imports de packages typo-squattés.

<a id="playbook-chaindrop"></a>
#### Playbook de réponse à incident

**Phase 1 - Préparation**
* Activer la journalisation des exécutions de process sur les postes de dev (Sysmon) et les runners CI.
* Mettre en place un supply chain monitor (ex : Elastic Supply Chain Monitor) pour détecter les packages npm malveillants.
* Recenser les dépôts utilisant un self-hosted remote cache et les packages de l'écosystème keyv/cacheable.
* Sauvegardes hors-ligne des repos et des configurations CI.

**Phase 2 - Détection et analyse**
* **Règles de détection contextualisées :**
  * Règle Sigma / Sysmon : création de fichiers `Math_Symbol.js`, `math_init.js`, `_helpers.js`, `.claude/setup.mjs`, `.vscode/setup.mjs` sur postes de dev et runners.
  * Détection YARA : signatures du payload CHAINDROP (control-flow flattening + Base91, strings Dune-themed : laza, kanly, ghola, mentat, lasgun, sietch, fedaykin, tleilaxu, sandworm, sardaukar, ornithopter, navigator).
  * Détection réseau : connexions vers `*.workers[.]dev` (oob-worker.cf103-070, oob-worker.cf102-baf, oob-worker.cf99-9b3) et requêtes DNS TXT vers `*.dl.wel1[.]ru`.
* Analyser les commits GitHub avec auteur « claude » et message « chore: update config » sur les repos accessibles.
* Chronologie des publications npm suspectes (timestamp court, packages typo-squattés).

**Phase 3 - Confinement, éradication et récupération**
* **Confinement :** isoler les postes de dev et runners compromis ; suspendre les pipelines CI utilisant les packages affectés ; bloquer les canaux C2 (Workers Cloudflare, `wel1[.]ru`).
* **Éradication :** supprimer les packages malveillants des lockfiles ; supprimer les hooks `.claude/settings.json` et `.vscode/tasks.json` injectés ; supprimer les credentials volés des stores (npm, GitHub, cloud, SSH).
* **Récupération :** restauration des repos depuis un commit sain antérieur ; rebuild des artefacts CI ; surveillance 72h post-restauration ; rotation de tous les credentials exposés.

**Phase 4 - Activités post-incident**
* Rapport distinguant les phases, MTTD/MTTR.
* REX avec les équipes dev et la direction.
* Partage des IOCs avec le CERT national.
* Notifications NIS2/RGPD si données personnelles exfiltrées via les runners CI.

**Phase 5 - Threat Hunting (proactif)**

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exécution de ChainDrop via hook SessionStart/folderOpen. | T1059.007 - JavaScript ; T1546 - Event Triggered Execution | Sysmon Event ID 1 & 11, EDR | `node` exécutant `setup.mjs` dans `.claude/` ou `.vscode/` au démarrage d'une session Claude Code ou ouverture de repo VS Code. |
| Persistance via commits worms sur 50 branches. | T1213 - Data from Information Repositories ; T1543 - Create/Modify System Process | GitHub audit logs | Commits avec auteur « claude » et message « chore: update config » sur multiples branches d'un même repo. |
| Exfiltration DNS TXT vers wel1.ru. | T1048.004 - Exfiltration Over Alternative Protocol | DNS logs, passive DNS | Requêtes TXT vers `*.dl.wel1[.]ru` et `c.sdk.dl.wel1[.]ru`, `0.sdk.dl.wel1[.]ru`, etc. |
| C2 reconfiguré via transaction Ethereum. | T1090 - Proxy | Blockchain explorer, EDR | Corrélation entre activités ChainDrop et transactions Ethereum inhabituelles (résolution C2 on-chain). |

<a id="ioc-chaindrop"></a>
#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `oob-worker.cf103-070[.]workers[.]dev` | C2 HTTPS principal CHAINDROP (Worker Cloudflare). | Haute |
| Domaine | `oob-worker.cf102-baf[.]workers[.]dev` | C2 HTTPS principal CHAINDROP (Worker Cloudflare). | Haute |
| Domaine | `oob-worker.cf99-9b3[.]workers[.]dev` | C2 HTTPS principal CHAINDROP (Worker Cloudflare). | Haute |
| Domaine | `wel1[.]ru` | Domaine de fallback DNS TXT (AI slopsquatting russe + possiblement CHAINDROP). | Haute |
| Domaine | `sdk.dl.wel1[.]ru` / `ext.dl.wel1[.]ru` / `pkg.dl.wel1[.]ru` / `net.dl.wel1[.]ru` | Sous-domaines de payload DNS TXT par plateforme (Linux x64/ARM64, macOS, Windows). | Haute |
| Package npm | `checkout-mobile-bnpl@35.6.9` | Package pivot de la campagne AI slopsquatting russe. | Haute |
| Fichier | `Math_Symbol.js` / `math_init.js` | Payload CHAINDROP (même hash SHA-256, filename = génération d'infection). | Haute |
| Fichier | `.claude/setup.mjs` / `.vscode/setup.mjs` | Droppers déclenchés à l'ouverture du repo. | Haute |
| Indicateur git | auteur commit « claude », message « chore: update config » | Marqueurs des commits worm-generated. | Haute |

<a id="ttp-chaindrop"></a>
#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise | Compromise Software Supply Chain : Compromise Software Supply Chain | Worm CHAINDROP compromettant le mainteneur npm et auto-répliquant via vol de token. |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Execution | JavaScript | Exécution du payload Node.js (`Math_Symbol.js`) via `bun`. |
| [T1546](https://attack.mitre.org/techniques/T1546/) | Persistence | Event Triggered Execution | Hooks `.claude/settings.json` (SessionStart) et `.vscode/tasks.json` (folderOpen). |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Credential Access | Unsecured Credentials | Credential harvester « collector » (300+ patterns, AI tooling credentials). |
| [T1048.004](https://attack.mitre.org/techniques/T1048/004/) | Exfiltration | Exfiltration Over Alternative Protocol : DNS TXT | Fallback DNS TXT sous `wel1[.]ru` (campagne AI slopsquatting). |
| [T1090](https://attack.mitre.org/techniques/T1090/) | Command and Control | Proxy | C2 via Workers Cloudflare + reconfigure on-chain Ethereum. |

<a id="sources-chaindrop"></a>
#### Sources

* [Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages (Elastic Security Labs)](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain)
* [ChainDrop: Inside a Self-Propagating npm Worm (Unit 42)](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
* [Russian AI Slopsquatting Publishes 700+ Malicious NPM Packages (OpenSourceMalware)](https://opensourcemalware.com/blog/russian-ai-slopsquatting-npm-campaign)

---

<a id="unc6671-vishing-extortion-multi-marques"></a>
### UNC6671 - Vishing extortion multi-marques (Redact/Pink/Helix/Falcon) cible financial services

<a id="resume-technique-unc6671"></a>
#### Résumé technique

Google Threat Intelligence Group (GTIG/Mandiant) continue de tracer UNC6671 malgré l'annonce de retraite du brand BlackFile en mai 2026. Au lieu de se dissoudre, UNC6671 a diversifié ses opérations d'extorsion à travers plusieurs fronts de marque : Redact, Pink, Helix et Falcon. La TTP reste constante : voice phishing (vishing) ciblant les employés enterprise en se faisant passer pour du staff IT helpdesk facilitant des migrations de sécurité urgentes, souvent via les mobiles personnels des victimes. Les appels redirigent vers des portails de login spoofés où une infrastructure Adversary-in-the-Middle (AiTM) intercepte credentials et tokens MFA. Une fois la persistance de session établie, les acteurs déploient des scripts automatisés d'exfiltration depuis les environnements cloud enterprise (Microsoft 365, Okta). Cibles récentes : financial services, private equity, professional services. Infrastructure partagée entre les marques : panels de credential harvesting sur des root domains génériques liés aux passkeys.

<a id="analyse-impact-unc6671"></a>
#### Analyse de l'impact

L'impact est direct pour les organisations dont les employés sont ciblés sur leurs mobiles personnels (vecteur hors périmètre IT classique). L'interception AiTM de credentials et MFA tokens contourne l'authentification forte, et l'exfiltration automatisée depuis M365/Okta peut compromettre l'ensemble des données SaaS de l'organisation. La diversification multi-marque complique l'attribution et le suivi des DLS pour les defenders.

<a id="recommandations-unc6671"></a>
#### Recommandations

* Durcir le helpdesk IT : processus de vérification d'identité robustes, formation anti-vishing, politique de rappel via canal officiel.
* Déployer des contrôles anti-AiTM : FIDO2/phishing-resistant MFA (passkeys) plutôt que OTP SMS/TOTP ; conditional access basé sur device posture.
* Surveiller les sessions M365/Okta inhabituelles (nouveaux refresh tokens, sessions persistantes post-changement de credentials).
* Bloquer les domaines de credential harvesting liés aux passkeys identifiés par GTIG.
* Former les employés à ne jamais traiter les demandes de migration de sécurité urgentes reçues par mobile personnel sans vérification.

<a id="playbook-unc6671"></a>
#### Playbook de réponse à incident

**Phase 1 - Préparation**
* Activer la journalisation M365/Okta (audit logs, sign-in logs, conditional access) et la centralisation SIEM.
* Déployer FIDO2/passkeys comme MFA phishing-resistant.
* Former le helpdesk IT aux procédures anti-vishing et de vérification d'identité.
* Identifier les employés à risque élevé (financial services, accès admin cloud).

**Phase 2 - Détection et analyse**
* **Règles de détection contextualisées :**
  * Règle Sigma / M365 : nouvelles sessions persistantes (refresh tokens) créées depuis des IP/attributs inhabituels peu après un changement de credentials.
  * Détection AiTM : patterns de user-agent et d'IP correspondant à des panels de harvesting connus.
* Analyser les logs de connexion MFA pour les échecs suivis de succès inhabituels (signe de relay AiTM).
* Chronologie des appels helpdesk suspects et des sessions cloud ultérieures.

**Phase 3 - Confinement, éradication et récupération**
* **Confinement :** révoquer les refresh tokens et sessions M365/Okta des comptes compromis ; isoler les devices suspects.
* **Éradication :** réinitialiser les credentials et MFA des comptes compromis ; supprimer les règles de forwarding/transport M365 malveillantes.
* **Récupération :** restaurer l'accès légitime ; surveillance 72h post-restauration.

**Phase 4 - Activités post-incident**
* Rapport distinguant les phases, MTTD/MTTR.
* REX avec le helpdesk IT et la direction.
* Partage des IOCs avec le CERT national.
* Notifications NIS2/RGPD si données personnelles exfiltrées depuis M365.

**Phase 5 - Threat Hunting (proactif)**

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Sessions M365 persistantes créées via AiTM. | T1556 - Modify Authentication Process ; T1078 - Valid Accounts | M365 sign-in logs | Refresh tokens créés depuis IP/user-agent inhabituels peu après login suspect. |
| Règles de forwarding M365 malveillantes. | T1564 - Hide Artifact ; T1020 - Exfiltration Over C2 | M365 audit logs | Règles de transport/forwarding créées vers des domaines externes inhabituels. |

<a id="ioc-unc6671"></a>
#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Cluster | UNC6671 (Mandiant) | Acteur d'extorsion multi-marques (BlackFile→Redact/Pink/Helix/Falcon), vishing + AiTM + exfil M365/Okta. | Haute |

<a id="ttp-unc6671"></a>
#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1566.004](https://attack.mitre.org/techniques/T1566/004/) | Initial Access | Vishing | Appels helpdesk IT spoofés vers mobiles personnels des employés. |
| [T1556](https://attack.mitre.org/techniques/T1556/) | Credential Access | Modify Authentication Process | AiTM interceptant credentials et tokens MFA. |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Defense Evasion | Valid Accounts | Persistance de session via tokens MFA valides. |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Exfiltration | Exfiltration Over C2 | Scripts automatisés d'exfiltration depuis M365/Okta. |

<a id="sources-unc6671"></a>
#### Sources

* [UNC6671 Rebrands: Multi-Brand Vishing Extortion Targets Financial Services and Enterprise Cloud Environments (Google GTIG/Mandiant)](https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments/)

---

<a id="snowflake-unc5537-plaidoyer-moucka"></a>
### Snowflake / UNC5537 - Plaidoyer de Connor Moucka (165 organisations, 100M+ personnes)

<a id="resume-technique-snowflake"></a>
#### Résumé technique

Connor Riley Moucka, 26 ans, de Kitchener (Ontario), a plaidé coupable le 05/08/2026 devant un tribunal fédéral de Washington à une conspiration de hacking informatique (février-octobre 2024) ayant compromis plus de 165 organisations, volé des milliards de records et extorqué de multiples victimes pour des millions de dollars. Le schème a ciblé les comptes clients de Snowflake (la « U.S.-based SaaS company » non nommée par le DoJ). Le détail technique qui a fait école : la plateforme Snowflake elle-même n'a jamais été compromise. Mandiant a attribué la campagne à UNC5537 et confirmé que les attaquants ont exploité des credentials valides mais exposées depuis longtemps (parfois 2020) collectées via infostealers sur les machines de dipendents/partners des entreprises clientes. L'absence systémique de MFA sur les comptes Snowflake a fait le reste. Moucka collaborait avec John Erin Binns (déjà lié au hack T-Mobile 2021, arrêté en Turquie en 2024). Victimes : AT&T (logs d'appels/SMS de 100M+ clients), Ticketmaster/Live Nation (560M utilisateurs), Advance Auto Parts, Santander, LendingTree, Neiman Marcus. ~2,5M$ de rançon perçus + 495k$ de revente sur BreachForums/XSS.is, une victime estortée deux fois (pression accrue avec données personnelles d'un ex-fonctionnaire et de sa famille). Risque jusqu'à 32 ans, sentencing le 27/10/2026.

<a id="analyse-impact-snowflake"></a>
#### Analyse de l'impact

Bien qu'il s'agisse d'un épilogue judiciaire, le pattern d'attaque reste un cas d'école pour les SOC/CERT : credentials valides issues d'infostealers + absence de MFA sur comptes cloud data warehouse = compromission massive. Le schème est reproductible contre tout SaaS d'entreprise dont les comptes ne sont pas MFA. Les données exfiltrées (logs appels/SMS, banking, payroll, DEA, passeports, SSN) relèvent de notification RGPD article 33/34 et NIS2 pour les entités essentielles/importantes.

<a id="recommandations-snowflake"></a>
#### Recommandations

* Imposer MFA (phishing-resistant, FIDO2/passkeys) sur tous les comptes cloud data warehouse et SaaS d'entreprise.
* Surveiller l'exposition de credentials dans les leaks d'infostealers (HaveIBeenPwned, services de dark web monitoring) et rotationner les credentials compromises.
* Activer les politiques conditional access (device posture, IP allowlist) sur les comptes SaaS.
* Journaliser et alerter sur les accès SaaS inhabituels (downloads massifs, nouvelles sessions depuis IP inhabituelles).
* Réviser les politiques de rétention de credentials et l'usage de service accounts.

<a id="playbook-snowflake"></a>
#### Playbook de réponse à incident

**Phase 1 - Préparation**
* Activer la journalisation des accès SaaS (Snowflake, M365, Okta, etc.) et la centralisation SIEM.
* Imposer MFA phishing-resistant (FIFO2/passkeys) sur tous les comptes cloud.
* Mettre en place un monitoring des leaks d'infostealers pour les credentials corporate.
* Recenser les service accounts et credentials non MFA.

**Phase 2 - Détection et analyse**
* **Règles de détection contextualisées :**
  * Règle Sigma / SaaS : accès cloud data warehouse depuis IP/attributs inhabituels sans MFA récente.
  * Détection : downloads massifs ou requêtes SQL inhabituelles depuis de nouvelles sessions.
* Analyser les logs de connexion pour les credentials compromises (corrélation avec les leaks d'infostealers).
* Chronologie des accès, volumes exfiltrés, comptes touchés.

**Phase 3 - Confinement, éradication et récupération**
* **Confinement :** révoquer les credentials et sessions compromises ; restreindre l'accès SaaS aux IP internes.
* **Éradication :** rotationner les credentials compromises ; activer MFA ; supprimer les comptes non autorisés.
* **Récupération :** restaurer l'accès légitime ; surveillance 72h post-restauration.

**Phase 4 - Activités post-incident**
* Rapport distinguant les phases, MTTD/MTTR.
* REX avec la direction.
* Notifications RGPD (art. 33/34) et NIS2 pour les entités essentielles/importantes.
* Partage des IOCs avec le CERT national.

**Phase 5 - Threat Hunting (proactif)**

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Credentials corporate dans les leaks d'infostealers. | T1552 - Unsecured Credentials | Dark web monitoring, HIBP | Corrélation entre emails corporate et credentials dans les dumps d'infostealers récents. |
| Accès SaaS sans MFA depuis IP inhabituelles. | T1078 - Valid Accounts | SaaS sign-in logs | Logins réussis sans MFA récente depuis IP/attributs inhabituels. |

<a id="ioc-snowflake"></a>
#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Cluster | UNC5537 (Mandiant) | Acteur nord-américain + collaborateur en Turquie (John Erin Binns), credentials valides + no-MFA SaaS. | Haute |
| Acteur | Connor Riley Moucka (aka « Waifu »/« Judishe ») | Plaidoyer coupable 05/08/2026, 26 ans, Kitchener Ontario. | Haute |

<a id="ttp-snowflake"></a>
#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1585](https://attack.mitre.org/techniques/T1585/) | Resource Development | Establish Accounts | Credentials valides issues d'infostealers (parfois 2020) réutilisées sur comptes SaaS. |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access | Valid Accounts | Accès via credentials valides sur comptes Snowflake sans MFA. |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Collection | Data from Information Repositories | Exfiltration massive de records depuis les data warehouse SaaS. |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Impact | Data Encrypted for Impact | Extorsion double de certaines victimes via menace de publication des données. | |

<a id="sources-snowflake"></a>
#### Sources

* [Snowflake Hacker Pleads Guilty After Breaching 165 Companies (securityaffairs)](https://securityaffairs.com/196714/security/snowflake-hacker-pleads-guilty-after-breaching-165-companies-and-stealing-billions-of-records.html)
* [Canadian Man Pleads Guilty in Snowflake Extortions (Krebs on Security)](https://krebsonsecurity.com/2026/08/canadian-man-pleads-guilty-in-snowflake-extortions/)
* [Snowflake, l'hacker Connor Moucka si dichiara colpevole (insicurezzadigitale)](https://insicurezzadigitale.com/snowflake-lhacker-connor-moucka-si-dichiara-colpevole-il-conto-finale-di-165-aziende-violate-e-miliardi-di-record-rubati/)
* [Snowflake Breaches Expose 100 Million People (Analyst207 mastodon)](https://mastodon.social/@Analyst207/117047168406079414)
* [Snowflake cyberattack Canadian pleads guilty (securityLab_jp mastodon)](https://mastodon.social/@securityLab_jp/117051071077294654)
* [Security Crawler Carl - Snowflake cutscene (infosec.exchange)](https://infosec.exchange/@security_crawler_carl/117046982433164539)

---

<a id="ssh-automate-22-secondes"></a>
### SSH automatisé - 22 secondes du login à la persistance (playbook honeypot)

<a id="resume-technique-ssh"></a>
#### Résumé technique

ISC SANS (Daryl Jiminez, intern BACS) documente depuis un honeypot Cowrie v2.3.0 sur Raspberry Pi 5 une intrusion SSH pleinement automatisée le 23/05/2026. Source IP `163[.]7[.]8[.]79`, authentification réussie en 1 seconde avec le credential faible `root`/`Aa123123123`, puis en 22 secondes : injection d'une backdoor SSH key (SHA-256 `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`), suppression et recréation du dossier `.ssh` pour éliminer les clés existantes, changement du mot de passe root, vidage de `/etc/hosts.deny` pour lever les restrictions d'accès, et reconnaissance automatisée. Sur 30 jours, le capteur a capturé 112 000+ sessions SSH et 72 000+ tentatives d'authentification depuis 175+ IPs malveillantes uniques. L'IP revenait plusieurs fois par jour avec un ordre de commandes et un timing identiques, confirmant un playbook pré-scripté exécuté dès l'authentification réussie.

<a id="analyse-impact-ssh"></a>
#### Analyse de l'impact

Le signal est opérationnel : les actors automatisés compressent la fenêtre post-auth à 22 secondes, laissant peu de temps à la détection humaine. Les credentials faibles et les credentials leaks restent un vecteur d'accès initial majeur sur les SSH exposés. Les SOCs doivent s'attendre à une persistance quasi-immédiate après compromission, et le threat hunting doit se concentrer sur les 60 premières secondes post-login.

<a id="recommandations-ssh"></a>
#### Recommandations

* Désactiver l'authentification par mot de passe SSH ; imposer l'authentification par clé uniquement.
* Imposer des mots de passe forts et uniques ; surveiller les credentials leaks (HIBP, dark web).
* Activer fail2ban ou équivalent pour limiter le brute-force.
* Surveiller les modifications de `.ssh/authorized_keys`, `/etc/shadow`, `/etc/hosts.deny` dans les 60 premières secondes post-login.
* Journaliser les commandes exécutées post-login SSH (auditd, Sysmon Linux).
* Restreindre l'accès SSH aux IP internes via VPN/bastion.

<a id="playbook-ssh"></a>
#### Playbook de réponse à incident

**Phase 1 - Préparation**
* Désactiver l'auth par mot de passe SSH ; clés uniquement ; rotationner les clés.
* Activer auditd/Sysmon Linux et la centralisation SIEM des logs SSH/auth.
* Déployer fail2ban et EDR Linux.
* Identifier les hôtes exposés SSH (scan interne + externe).

**Phase 2 - Détection et analyse**
* **Règles de détection contextualisées :**
  * Règle Sigma / auditd : modification de `.ssh/authorized_keys`, `/etc/shadow`, `/etc/hosts.deny` dans les 60s suivant un login SSH réussi.
  * Détection : commandes de reconnaissance inhabituelles (`whoami`, `uname -a`, `id`, `ls`) immédiatement après login.
* Analyser les logs SSH pour les logins réussis depuis IP suspectes et les commandes post-login.
* Chronologie : login → key injection → password change → reconnaissance.

**Phase 3 - Confinement, éradication et récupération**
* **Confinement :** isoler l'hôte compromis ; bloquer l'IP source.
* **Éradication :** supprimer les backdoor SSH keys ; réinitialiser le mot de passe root ; restaurer `/etc/hosts.deny` ; supprimer les éventuels implants.
* **Récupération :** restaurer depuis une sauvegarde saine ; surveillance 72h post-restauration.

**Phase 4 - Activités post-incident**
* Rapport distinguant les phases, MTTD/MTTR.
* Partage des IOCs avec le CERT national.
* Notifications si impact.

**Phase 5 - Threat Hunting (proactif)**

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Backdoor SSH key injectée post-login. | T1098.004 - SSH Authorized Keys | auditd logs, EDR | Modifications de `.ssh/authorized_keys` dans les 60s suivant un login SSH réussi. |
| Vidage de `/etc/hosts.deny`. | T1562 - Impair Defenses | auditd logs | Modifications de `/etc/hosts.deny` ou `/etc/hosts.allow` post-login. |

<a id="ioc-ssh"></a>
#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `163[.]7[.]8[.]79` | Source IP de l'intrusion honeypot (23/05/2026). | Haute |
| Hash SHA-256 | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | Clé SSH backdoor injectée. | Haute |
| Credential | `root` / `Aa123123123` | Credential faible utilisé (cycles de breaches). | Haute |

<a id="ttp-ssh"></a>
#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access | Valid Accounts | Authentification via credential faible `root`/`Aa123123123`. |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | Persistence | SSH Authorized Keys | Injection de backdoor SSH key et suppression des clés existantes. |
| [T1562](https://attack.mitre.org/techniques/T1562/) | Defense Evasion | Impair Defenses | Vidage de `/etc/hosts.deny` pour lever les restrictions d'accès. |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Execution | Unix Shell | Reconnaissance automatisée post-login. |

<a id="sources-ssh"></a>
#### Sources

* [22 Seconds to Compromise: How Automated SSH Actors Move From Login to Persistence Before You Can Blink (ISC SANS)](https://isc.sans.edu/diary/rss/33220)

---

<a id="rockwell-plc-exposes-eau-4400-controleurs-22-villes-attaquees"></a>
### Rockwell PLCs exposés - 4400 contrôleurs, 22 dans villes attaquées sur l'eau

<a id="resume-technique-rockwell"></a>
#### Résumé technique

Forescout recense 4407 contrôleurs Rockwell/Allen-Bradley exposés sur Internet (scan du 03/08), dont 2844 aux États-Unis, et identifie 22 contrôleurs dans des villes US touchées par les récentes cyberattaques contre des services d'eau (19 sur le même opérateur mobile). Les effets décrits publiquement n'ont pas nécessité d'exploit : les attaquants ont changé des adresses IP et défini des mots de passe sur des contrôleurs déjà accessibles, faisant perdre la visibilité et parfois le contrôle aux opérateurs. Depuis le 27/07, des utilités d'eau/wastewater dans 7+ États ont signalé des incidents (FBI/EPA, 30/07). EtherNet/IP sur port 44818 expose un chemin non authentifié permettant d'identifier un contrôleur ou d'écrire des settings selon la config. 70%+ des contrôleurs US exposés tournent sur grands opérateurs cellulaires (Verizon, AT&T, T-Mobile). MicroLogix 1400 = 50% des résultats, MicroLogix 1100 = 8% (discontinué le 30/04/2022). 19 des 22 contrôleurs en villes attaquées tournaient un firmware sensible à CVE-2017-16740 (Modbus TCP buffer overflow, MicroLogix 1400 Series B/C firmware ≤ 21.002, fix en 21.003). Forescout n'a pas pu confirmer l'exploitation sur ces hôtes. Aucune attribution du campaign.

<a id="analyse-impact-rockwell"></a>
#### Analyse de l'impact

L'OT/eau est une infrastructure critique où la disponibilité est essentielle. L'exposition Internet directe de PLCs est une faille de conception opérationnelle : un attaquant peut changer des settings et faire perdre le contrôle sans exploit. La CVE-2017-16740 (Rockwell CVSS 8.6) reste exploitable sur des firmwares non patchés. Le caractère non attribué et la concentration sur un même opérateur mobile suggèrent soit une sélection opportuniste soit une connaissance préalable des cibles.

<a id="recommandations-rockwell"></a>
#### Recommandations

* Retirer les contrôleurs Rockwell de l'exposition Internet publique ; les placer derrière un private APN, VPN ou architecture similaire.
* Activer l'authentification forte, les updates et le logging des modems cellulaires (reco FBI/EPA).
* Mettre à jour les firmwares MicroLogix 1400 ≥ 21.003 (fix CVE-2017-16740).
* Pour les opérateurs verrouillés par un mot de passe attaquant : suivre l'advisory SD1790 (reset factory + redownload d'un projet known-good), nécessite une copie hors-ligne du contrôleur logic.
* Surveiller les ladder logic discrepancies entre sites (signe de modification des PLC project files).
* Isoler les configurations tierces partageant des setups vulnérables (risque de compromission répétée).

<a id="playbook-rockwell"></a>
#### Playbook de réponse à incident

**Phase 1 - Préparation**
* Recenser tous les PLCs et équipements OT exposés (scans Censys/Forescout).
* Identifier les configurations partagées tierces et les opérateurs cellulaires.
* Maintenir des copies hors-ligne des PLC project files.
* Définir un plan de coupure réseau OT et de bascule manuelle.

**Phase 2 - Détection et analyse**
* **Règles de détection contextualisées :**
  * Règle OT/ICS : connexions non authentifiées sur EtherNet/IP port 44818 depuis IP externes.
  * Détection : changements d'adresse IP et de mot de passe sur PLCs, ladder logic discrepancies entre sites.
* Analyser les logs de modem/cellular gateway pour les accès inhabituels.
* Chronologie des incidents par État depuis le 27/07.

**Phase 3 - Confinement, éradication et récupération**
* **Confinement :** retirer les PLCs d'Internet (coupure liaison publique) ; basculer en contrôle manuel si nécessaire.
* **Éradication :** reset factory des contrôleurs verrouillés (SD1790) ; redownload d'un projet known-good ; patch firmware ≥ 21.003.
* **Récupération :** surveillance 72h post-restauration ; vérifier les ladder logic sur tous les sites.

**Phase 4 - Activités post-incident**
* Rapport distinguant les phases, MTTD/MTTR.
* REX avec les équipes OT et la direction.
* Notifications NIS2 (eau = entité essentielle) et autorités sectorielles.
* Partage des IOCs avec le CERT national et les ISAC sectoriels.

**Phase 5 - Threat Hunting (proactif)**

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Accès non authentifié EtherNet/IP port 44818. | T0817 - Drive | OT/ICS logs, network monitoring | Connexions externes sur port 44818 sans auth ; écritures de settings inhabituelles. |
| Exploitation CVE-2017-16740 Modbus TCP. | T0866 - Exploitation | OT/IDS | Paquets Modbus TCP malformés ciblant MicroLogix 1400 firmware ≤ 21.002. |

<a id="ioc-rockwell"></a>
#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| CVE | CVE-2017-16740 | Modbus TCP buffer overflow, MicroLogix 1400 Series B/C firmware ≤ 21.002 (fix 21.003), Rockwell CVSS 8.6. | Haute |
| Port | 44818 (EtherNet/IP) | Surface d'exposition non authentifiée des PLCs Rockwell. | Haute |

<a id="ttp-rockwell"></a>
#### TTP MITRE ATT&CK (ICS)

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T0817](https://attack.mitre.org/techniques/T0817/) | Inhibit Response Function | Drive | Changement d'adresse IP et de mot de passe sur PLCs déjà accessibles. |
| [T0866](https://attack.mitre.org/techniques/T0866/) | Execution | Exploitation | Exploitation potentielle de CVE-2017-16740 (Modbus TCP buffer overflow). |

<a id="sources-rockwell"></a>
#### Sources

* [Over 4,400 Rockwell PLCs Exposed Online, 22 Found in Water Attack Cities (thehackernews)](https://thehackernews.com/2026/08/over-4400-rockwell-plcs-exposed-online.html)

---

<a id="autres-hors-perimetre"></a>
## Autres / hors-périmètre

Clusters à faible actionnabilité SOC/CERT directe ou hors périmètre cyber offensif, signalés pour arbitrage.

### Data breaches divers (regroupement)

| Victime | Secteur / pays | Description | Source(s) |
|---|---|---|---|
| **SISVISA** (Brésil) | Santé / surveillance sanitaire | Base de données SISVISA (Health Surveillance Information System) exposée sans auth : 102 215 fichiers, ~79 GB. Données : noms, adresses, téléphones, CPF/CNPJ, scans de permis et cartes médecin. Trouvé par Jeremiah Fowler (ExpressVPN). | [securityaffairs](https://securityaffairs.com/196766/data-breach/exposed-sisvisa-database-leaks-102000-brazilian-health-surveillance-records.html) |
| **Inter-Con Security** (US) | Sécurité physique | 276 114 comptes (emails, noms, adresses, fonctions, téléphones) publiés par ShinyHunters dans une campagne « pay or leak » de juin 2026. Ajouté à HIBP le 05/08 (48 jours après l'incident). Stack : Cloudflare, WordPress ; pas de SPF/DMARC. | [HIBP](https://haveibeenpwned.com/Breach/InterConSecurity), [RedPacketSecurity](https://mastodon.social/@RedPacketSecurity/117046093701416907), [BeeSINT](https://mastodon.social/@BeeSINT/117045543011237044) |
| **Orova / Cardiology Associates of Port Huron** (US) | Santé / extortion | Nouveau groupe ransomware « Orova », ~50 victimes dans 6 pays depuis début mai, 3 entités médicales US (Wisdom Oral Surgery NJ : 20 308 fichiers / 29,6 GB ; Cardiology Associates of Port Huron MI ; Magnolia Dental FL). | [databreaches](https://databreaches.net/2026/08/06/cardiology-associates-of-port-huron-remains-silent-although-they-were-allegedly-hacked-and-had-patient-data-stolen-in-june/) |
| **Bol / De Bijenkorf** (Pays-Bas) | Retail | Le retailer néerlandais Bol suit De Bijenkorf dans l'avertissement d'un data breach alors que des données leakées apparaissent sur le dark web. Incident chez un partenaire logistique (CEVA Logistics). | [databreaches](https://databreaches.net/2026/08/06/dutch-retailer-bol-follows-de-bijenkorf-in-warning-of-data-breach-as-leaked-data-appears-on-dark-web/), [beyondmachines1 (mastodon)](https://infosec.exchange/@beyondmachines1/117048691331019200) |
| **SplitVPN** | VPN | Data breach exposant les records personnels de 865k utilisateurs (archive CyberIntel). | [cyberintelnews (mastodon)](https://mastodon.social/@cyberintelnews/117045618442708246) |

### Notes et recherches

- **Token Jacking (Unit 42)** : cybercriminels volent les API keys (tokens) des développeurs pour accéder aux plateformes IA et revendre la capacité. Pertes financières massives via scaling illimité. Reco : hygiène des clés, Prisma AIRS AI Gateway, rotation. Lien avec la thématique agents IA du jour. [Unit 42](https://unit42.paloaltonetworks.com/ai-token-jacking/)
- **Smartwatch pour enfants détourné en stalking (WIRED)** : un chercheur (Vangelis Stykas) a démontré le hijack d'une smartwatch enfant pour suivre un reporter. Signal IoT consumer. [WIRED](https://www.wired.com/story/hackers-stalked-me-by-hijacking-a-smartwatch-for-kids/)
- **FreeBSD security model « The Taking of FreeBSD One Two Three »** : deep dive sur le modèle de sécurité et la surface d'attaque de FreeBSD ; la « assumption-based security » (BSD = niche = sûr) est une vulnérabilité en soi. [malware.news via Bobe_bot](https://mastobot.ping.moi/@Bobe_bot/117050809696992411)
- **Zero Trust Meets the AI Era (Guidepoint/Zscaler)** : Zero Trust évolue pour sécuriser les agents IA, identités machine et écosystèmes digitaux dynamiques. [Guidepoint](https://www.guidepointsecurity.com/blog/zero-trust-meets-the-ai-era/)
- **ThreatsDay roundup (thehackernews)** : bulletin hebdomadaire couvrant aussi Odysseus RCE, Samsung One-Click Takeover, iCloud Backdoor Fight (+27 stories), et le rapport « Stranger Pings » sur les télécoms chinoises aux US. [thehackernews](https://thehackernews.com/2026/08/threatsday-odysseus-rce-samsung-one.html)

### Filtrés (bruit / vide)

27 articles filtrés : annonces vides (OpenBao v2.6, ISC Stormcast, Talos blog, ENISA newsletter login page), posts communautaires sans substance (mèmes firewall, passwords aléatoires, promo InfoSecSherpa, Hacker Summer Camp), pages mastodon/telegram vides (Kodak 2,2M, Revolut Lituanie 50k, Ontario hospital, CRA lawsuit, Financial services incidents, SISVISA duplicate, UK PNLD, UKGI, empty cbc mirrors), Krebs (juste commentaires), ClickFix macOS (bleepingcomputer/mastodon vides), Roumanie immobilier hors sujet.
