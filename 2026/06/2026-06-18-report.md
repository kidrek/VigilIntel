# Rapport CTI — 2026-06-18

## Table des matières

- [Résumé stratégique](#résumé-stratégique)
- [Synthèse des vulnérabilités](#synthèse-des-vulnérabilités)
- [Synthèse des acteurs de menace](#synthèse-des-acteurs-de-menace)
- [Synthèse des compromissions de données](#synthèse-des-compromissions-de-données)
- [Synthèse géopolitique](#synthèse-géopolitique)
- [Synthèse réglementaire](#synthèse-réglementaire)
- [Articles détaillés](#articles-détaillés)

## Résumé stratégique

La volumétrie du jour est nettement dominée par les vulnérabilités (19) et les articles de veille (23), confirmant une pression persistante sur la surface d'attaque technique et un flux informationnel soutenu. Le signal threat actors (12) demeure élevé, signalant une activité structurée de groupes identifiés qui doit primer dans le triage analytique. Les compromissions de données (5) traduisent un impact opérationnel concret mais contenu, à corréler avec les acteurs évoqués. Les dimensions géopolitiques (3) et réglementaires (3) restent en retrait quantitatif, mais leur faible volume ne doit pas masquer leur effet structurant sur la menace, notamment en termes d'attribution et de conformité. Priorité CTI : approfondir les CVE critiques et les TTPs des acteurs les plus actifs, tout en veillant à l'intégration des signaux régulatoires susceptibles d'infléchir les scénarios d'exposition.

## Synthèse des vulnérabilités

Tableau trié : **CISA KEV → exploitation active → CVSS décroissant**.

| CVE | Produit / Vendeur | CVSS | EPSS | CISA KEV | Exploitation | Sources |
|---|---|---|---|---|---|---|
| CVE-2026-48907 | Widget Factory Joomla Content Editor (JCE) 1.0.0 – 2.9.99.4 | 10.0 | — | ✅ | Active | [thehackernews](https://thehackernews.com/2026/06/cisa-warns-of-actively-exploited-joomla.html) · [securityaffairs](https://securityaffairs.com/193775/hacking/u-s-cisa-adds-widget-factory-joomla-content-editor-jce-flaw-to-its-known-exploited-vulnerabilities-catalog.html) · [security.nl](https://www.security.nl/posting/940927/Joomla-websites+aangevallen+via+kritiek+beveiligingslek+in+JCE-editor?channel=rss) |
| CVE-2026-40783 | Blocksy Companion Pro (WordPress) ≤ 2.1.37 | 9.9 | — | ❌ | Active | [valtersit](https://www.valtersit.com/cve/CVE-2026-40783/) · [mastodon](https://mastodon.social/@hugovalters/116769368704116456) |
| CVE-2026-20253 | Splunk Enterprise 10.0.0–10.0.6 et 10.2.0–10.2.3 (PostgreSQL sidecar) | 9.8 | — | ❌ | Active | [fieldeffect](https://fieldeffect.com/blog/exploited-splunk-vulnerability-rce) |
| CVE-2026-12569 | PTC Windchill PDMlink / FlexPLM (< 11.0 M030) | 9.3 | — | ❌ | Theoretical | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-12569) · [cve.org](http://www.cve.org/CVERecord?id=CVE-2026-12569) |
| CVE-2026-48989 | Windows-MCP < 0.7.5 | 8.9 | — | ❌ | Theoretical | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-48989) · [cve.org](http://www.cve.org/CVERecord?id=CVE-2026-48989) |
| CVE-2026-53676 | ThingsBoard (IoT platform) | 8.6 | — | ❌ | Theoretical | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-53676) · [cve.org](http://www.cve.org/CVERecord?id=CVE-2026-53676) |
| CVE-2026-11407 | Pimcore CMS/DXP 12.3.8 | 8.6 | — | ❌ | Theoretical | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-11407) · [cve.org](http://www.cve.org/CVERecord?id=CVE-2026-11407) |
| CVE-2026-12530 | AWS Bedrock AgentCore Python SDK (1.1.3 – < 1.6.1) | 8.4 | — | ❌ | Theoretical | [aws security bulletin](https://aws.amazon.com/security/security-bulletins/rss/2026-044-aws/) · [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-12530) · [cve.org](http://www.cve.org/CVERecord?id=CVE-2026-12530) |
| CVE-2026-50194 | Steeltoe management endpoints 3.2.2–3.3.0 et 4.1.0 | 8.2 | — | ❌ | Theoretical | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-50194) · [cve.org](http://www.cve.org/CVERecord?id=CVE-2026-50194) |
| CVE-2026-50656 | Microsoft Defender / MsMpEng (« RoguePlanet ») | 7.8 | — | ❌ | Active | [thehackernews](https://thehackernews.com/2026/06/microsoft-confirms-rogueplanet-defender_02022423645.html) · [thecyberthrone](https://thecyberthrone.in/2026/06/17/rogueplanet-zero-day-microsoft-defender/) · [security.nl](https://www.security.nl/posting/940914/Microsoft+verwacht+misbruik+van+%27RoguePlanet-lek%27+in+Defender%2C+werkt+aan+update?channel=rss) |
| CVE-2026-12289 | Mozilla Firefox < 152 / Firefox ESR < 140.12 et < 115.37 / Thunderbird < 152 | — | — | ❌ | None | [certfr-2026-avi-0764](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0764/) · [mozilla](https://www.mozilla.org/en-US/security/advisories/mfsa2026-56/) |
| CVE-2026-12437 | Google Chrome < 149.0.7827.155 (Win/Linux) / 149.0.7827.156 (Mac) | — | — | ❌ | None | [certfr-2026-avi-0761](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0761/) · [chromereleases](https://chromereleases.googleblog.com/2026/06/stable-channel-update-for-desktop_01750511403.html) |
| CVE-2026-46850 | Oracle MySQL Server 8.0.x / 8.4.x / 9.x (CPU juin 2026) | — | — | ❌ | None | [certfr-2026-avi-0765](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0765/) · [oracle cspujun2026](https://www.oracle.com/security-alerts/cspujun2026.html) |
| CVE-2026-35271 | Oracle PeopleSoft Campus Community / Student Financials / PeopleTools | — | — | ❌ | None | [certfr-2026-avi-0766](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0766/) · [oracle cspujun2026](https://www.oracle.com/security-alerts/cspujun2026.html) |
| CVE-2025-59382 | Qnap QTS / QuTS hero / QuTS cloud / QVP / QuMagie / License Center | — | — | ❌ | None | [certfr-2026-avi-0762](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0762/) · [qsa-26-10](https://www.qnap.com/go/security-advisory/qsa-26-10) · [qsa-26-35](https://www.qnap.com/go/security-advisory/qsa-26-35) |
| CVE-2026-10831 | Moxa CN2600 Series < 4.6.11 / NPort 6000 Series < 2.3.9 | — | — | ❌ | None | [certfr-2026-avi-0763](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0763/) · [moxa advisory](https://www.moxa.com/en/support/product-support/security-advisory/mpsa-262370-cve-2026-10831-improper-authorization-vulnerability-in-serial-device-servers) |
| CVE-2025-20701 | Apple Beats Studio Buds (firmware < B211, SDK Airoha) | — | — | ❌ | Theoretical | [security.nl](https://www.security.nl/posting/940938/Bluetooth-lek+in+Apple+Beats+Studio+Buds+maakt+afluisteren+gebruikers+mogelijk?channel=rss) |
| CVE-2026-8049 | SignalRGB drivers (SignalIo.sys / SignalRgbDriver.sys < 1.3.7.0) | — | — | ❌ | Theoretical | [cert/CC VU#380058](https://kb.cert.org/vuls/id/380058) |
| CVE-2026-8863 | Bootloaders UEFI shim signés Microsoft (pré-DBX) | — | — | ❌ | Theoretical | [cert/CC VU#616257](https://kb.cert.org/vuls/id/616257) |

## Synthèse des acteurs de menace

| Acteur | Alias | Type | Secteurs ciblés | MITRE TTPs clés | Sources |
|---|---|---|---|---|---|
| Groupe russophone multi-opérateurs (FortiBleed) | — | Cybercriminel / sponsorisé par État (présumé) | Défense, infrastructures critiques, VPN/SSL | T1110.004, T1110.002, T1110.003, T1078.001, T1021, T1558, T1556, T1071, T1595, T1590, T1589, T1041, T1567 | [bleepingcomputer](https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/) · [arstechnica](https://arstechnica.com/security/2026/06/massive-breach-spills-credentials-for-thousands-of-sensitive-networks/) |
| ShinyHunters | UNC6040 (attribution possible) | Cybercriminel d'extorsion | Services financiers, conseil | T1657, T1567, T1590, T1591, T1592 | [haveibeenpwned](https://haveibeenpwned.com/Breach/CFGI) |
| Acteur non attribué (Tullamore / HSE) | — | Non attribué | Santé, hôpitaux publics Irlande | T1530, T1078, T1119, T1591, T1592 | [databreaches.net](https://databreaches.net/2026/06/17/ie-hse-fined-e300000-after-tullamore-hospital-data-breach/?pk_campaign=feed&pk_kwd=ie-hse-fined-e300000-after-tullamore-hospital-data-breach) |
| Qilin | Agenda, Phantom Piranha | Ransomware (RaaS) | Éducation K-12, mineurs, Australie | T1486, T1657, T1490, T1027, T1485, T1059, T1086, T1003, T1021, T1078, T1567 | [cyberdaily.au](https://www.cyberdaily.au/security/13766-exclusive-qilin-ransomware-claims-hack-of-aussie-k-12-tutoring-provider) |
| Acteur non attribué (iRhythm) | — | Ransomware / extorsion (présumé) | Santé, MedTech, dispositifs médicaux | T1657, T1567, T1486, T1530, T1003, T1078, T1021, T1591 | [bleepingcomputer](https://www.bleepingcomputer.com/news/security/irhythm-discloses-data-breach-says-hackers-stole-patient-info/) |
| Articles pédagogiques/communautaires | — | Non applicable | N/A | T1572, T1090, T1071.001, T1574.006, T1027.013, T1620, T1562.010, T1070 | [isc.sans.edu 33088](https://isc.sans.edu/diary/rss/33088) · [isc.sans.edu 33082](https://isc.sans.edu/diary/rss/33082) · [isc.sans.edu 33084](https://isc.sans.edu/diary/rss/33084) · [any.run](https://any.run/cybersecurity-blog/triage-analyst-guide/) · [cocomelonc](https://cocomelonc.github.io/linux/2026/06/17/linux-hacking-11.html) · [reddit WASMForge](https://www.reddit.com/r/redteamsec/comments/1u8b73j/wasmforge_a_builder_for_virtualizing_your_go_or_c/) · [reddit BroVan](https://www.reddit.com/r/redteamsec/comments/1u84s19/brovan_windows_linux_emulator_for_reverse/) · [reddit QoS](https://www.reddit.com/r/redteamsec/comments/1u85euf/qos_policies_to_restrict_edr_traffic_and/) · [vxunderground](https://t.me/vxunderground/8967) · [implicator](https://www.implicator.ai/repo-radar-5-github-projects-worth-your-week-8/) · [mastodon schuler](https://mastodon.social/@schuler/116769409000961735) · [infosec.exchange DevaOnBreaches](https://infosec.exchange/@DevaOnBreaches/116768565832607415) · [infosec.exchange DysruptionHub](https://infosec.exchange/@DysruptionHub/116768106137521162) · [infosec.exchange beyondmachines1](https://infosec.exchange/@beyondmachines1/116766756459144565) · [infosec.exchange edwardk 1](https://infosec.exchange/@edwardk/116767765483727168) · [infosec.exchange edwardk 2](https://infosec.exchange/@edwardk/116767609265594706) · [infosec.exchange shodansafari](https://infosec.exchange/@shodansafari/116769345526915247) |
| Opérateurs InfoStealers (multi) | LummaC2, RedLine, StealC, Raccoon | Crimeware / logs market | Tous secteurs, SaaS/Cloud | T1555.003, T1539, T1078.004 | [flare.io](https://flare.io/learn/resources/blog/stealerlens-stealer-log-analysis) |
| Acteurs étatiques (multi) | APT-Q-27 | APT / Étatique | Gouvernements, OIV, cibles géopolitiques | — | [recordedfuture](https://www.recordedfuture.com/research/state-digital-surveillance-risk-landscape) · [otx alienvault](https://otx.alienvault.com/pulse/6a337898ca771cf92e8adfa7) · [social.raytec](https://social.raytec.co/@techbot/116769367087381981) |
| Groupes cybercriminels / crimeware (multi) | LLMjacking, EDR evasion, RMM abuse, EdTech | Crimeware multi-acteurs | EdTech, HVAC, Cloud/AI, PME | T1219, T1059, T1078.002, T1543, T1105, T1027, T1486, T1530, T1562.010, T1070, T1090, T1565.002, T1078, T1550.001, T1496 | [redcanary](https://redcanary.com/blog/security-operations/rmm-detection/) · [databreaches.net EdTech](https://databreaches.net/2026/06/17/cybercriminals-are-targeting-edtech-data-breaches-and-ransomware-attacks-on-the-rise/?pk_campaign=feed&pk_kwd=cybercriminals-are-targeting-edtech-data-breaches-and-ransomware-attacks-on-the-rise) · [infosec.exchange XposedOrNot](https://infosec.exchange/@XposedOrNot/116769549622474656) · [sysdig](https://webflow.sysdig.com/blog/llmjacking-evolved-attackers-are-using-stolen-ai-compute-to-build-offensive-agentic-tools) |
| Bluekit (PhaaS) | — | PhaaS | Grand public / entreprises | T1566, T1583.001 | [otx alienvault](https://otx.alienvault.com/pulse/6a337860ca771cf92e8adfa6) · [social.raytec](https://social.raytec.co/@techbot/116769367156251346) |
| Employé hospitalier indélicat | — | Insider | Santé (NHS), données VIP | T1213, T1078.004 | [databreaches.net](https://databreaches.net/2026/06/17/hospital-worker-suspected-of-accessing-princess-of-waless-medical-records-to-face-prosecution/) |
| Acteurs supply-chain (worm GitHub, Mastra/NPM, Uncanny Automator) | — | Cybercriminel supply-chain | Développeurs, sites WordPress, entreprises consommatrices | T1195.002, T1190, T1059, T1059.006, T1546, T1505.003 | [databreaches.net worm](https://databreaches.net/2026/06/17/github-dismissed-security-reports-on-flaws-now-exploited-by-supply-chain-worm-researchers-say/?pk_campaign=feed&pk_kwd=github-dismissed-security-reports-on-flaws-now-exploited-by-supply-chain-worm-researchers-say) · [microsoft mastra](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/) · [infosec.exchange bugxhunter](https://infosec.exchange/@bugxhunter/116769586435461375) · [insicurezzadigitale](https://insicurezzadigitale.com/supply-chain-attack-su-uncanny-automator-pro-build-backdoorata-v7-3-0-5-distribuita-a-migliaia-di-siti-wordpress/) |

## Synthèse des compromissions de données

| ID | Victime | Secteur | Volume estimé | Acteur | Sources |
|---|---|---|---|---|---|
| DB-2026-06-17-001 | Multi-secteurs (73 932 appliances Fortinet/FortiGate, 194 pays) | Multi-sectoriel | 73 932 | Groupe russophone multi-opérateurs | [bleepingcomputer](https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/) · [arstechnica](https://arstechnica.com/security/2026/06/massive-breach-spills-credentials-for-thousands-of-sensitive-networks/) |
| DB-2026-06-18-002 | CFGI (société américaine de conseil financier) | Conseil financier | 248 235 | ShinyHunters | [haveibeenpwned](https://haveibeenpwned.com/Breach/CFGI) |
| DB-2026-06-17-003 | HSE (Hôpital de Tullamore, Irlande) | Santé publique | — | Non attribué | [databreaches.net](https://databreaches.net/2026/06/17/ie-hse-fined-e300000-after-tullamore-hospital-data-breach/?pk_campaign=feed&pk_kwd=ie-hse-fined-e300000-after-tullamore-hospital-data-breach) |
| DB-2026-06-18-004 | Fournisseur australien de soutien scolaire K-12 | Éducation K-12 | — | Qilin | [cyberdaily.au](https://www.cyberdaily.au/security/13766-exclusive-qilin-ransomware-claims-hack-of-aussie-k-12-tutoring-provider) |
| DB-2026-06-18-005 | iRhythm Technologies (MedTech) | Dispositifs médicaux | — | Non attribué (rançongiciel/extorsion) | [bleepingcomputer](https://www.bleepingcomputer.com/news/security/irhythm-discloses-data-breach-says-hackers-stole-patient-info/) |

## Synthèse géopolitique

| ID | Date | Thème | Régions | Secteur | Sources |
|---|---|---|---|---|---|
| G1 | 2026-06-17 | Influenceurs IA pro-algériens, subversion en ligne | France, Algérie, Amérique latine | Médias et réseaux sociaux | [portail-ie.fr](https://www.portail-ie.fr/univers/2026/influenceurs-ia-algeriens-de-nouveaux-acteurs-de-subversion-en-ligne/) |
| G2 | 2026-06-17 | Yandex, censure et alignement idéologique de l'IA par le Kremlin | Russie, ex-URSS, UE | Technologie / moteurs de recherche | [euvsdisinfo.eu](https://euvsdisinfo.eu/yandex-from-tech-innovation-to-information-control/) |
| G3 | 2026-06-17 | Souveraineté numérique : Palantir vs ChapsVision (DGSI) et divergence FR/UK | France, UK, US, UE | Défense, renseignement, IT | [lemonde.fr DGSI](https://www.lemonde.fr/societe/article/2026/06/17/renseignement-le-remplacement-de-palantir-par-le-francais-chapsvision-a-la-dgsi-un-choix-de-souverainete-au-long-cours-et-complexe_6704166_3224.html) · [lemonde.fr UK](https://www.lemonde.fr/economie/article/2026/06/17/au-royaume-uni-palantir-technologies-multiplie-les-contrats-et-les-critiques_6704198_3234.html) |

## Synthèse réglementaire

| ID | Date | Référence | Autorité | Juridiction | Sources |
|---|---|---|---|---|---|
| RL-001 | 2026-06-17 | Digital Decade Policy Programme – 2026 State of the Digital Decade | Commission européenne (DG Connect) | UE (27) | [digital-strategy news](https://digital-strategy.ec.europa.eu/en/news/2026-state-digital-decade-report-shows-progress-urges-closing-structural-gaps-reach-2030-goals) · [factsheet](https://digital-strategy.ec.europa.eu/en/library/state-digital-decade-2026-factsheet) · [MCP progress report](https://digital-strategy.ec.europa.eu/en/library/digital-decade-2026-progress-report-multi-country-projects) · [monitoring recommendations](https://digital-strategy.ec.europa.eu/en/library/digital-decade-2026-monitoring-2025-eu-level-recommendations) · [closing structural gaps](https://digital-strategy.ec.europa.eu/en/library/state-digital-decade-2026-closing-structural-gaps-and-mobilising-investments-2030-and-beyond) · [DESI methodological note](https://digital-strategy.ec.europa.eu/en/library/digital-decade-2026-desi-methodological-note) |
| RL-002 | 2026-06-17 | Google – IP pour mesure/ciblage publicitaire (EEE/UK/CH) – entrée 3 août 2026 | ICO (UK) / Régulateurs UE | EEE, UK, Suisse | [bleepingcomputer](https://www.bleepingcomputer.com/news/security/google-to-use-uk-and-eu-user-ip-addresses-for-ad-personalization/) |
| RL-003 | 2026-06-17 | Inde – blocage Telegram jusqu'au 22 juin 2026 (IT Act §69A) + BGP hijacking AS18101 | MeitY / NTA / Delhi High Court | Inde (+ impact UAE) | [bleepingcomputer](https://www.bleepingcomputer.com/news/security/indias-telegram-ban-hit-the-uae-too-heres-how-to-get-around-it/) |

## Articles détaillés

### ART-001 – ISC Stormcast (17 et 18 juin 2026)
- **Secteur** : Tous secteurs
- **Acteur** : Non attribué
- **Tags** : isc, stormcast, podcast, threat-intel
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : Bulletins quotidiens SANS ISC synthétisant les actualités threat intel. Pas d'incident spécifique dans le flux RSS.
- **Recommandations** : Suivre quotidiennement les Stormcasts ; intégrer les IoC publiés au SIEM ; corréler les éléments mentionnés avec les journaux internes.
- **Playbook** : Préparation (maintenir un playbook de veille CTI et intégrer le flux SANS), Détection (normaliser les IoC, corréler avec les logs SIEM/EDR/IDS), Confinement (isoler les correspondances, bloquer au niveau DNS/proxy/EDR), Post-incident (mettre à jour le référentiel CTI), Chasse (utiliser les IoC pour chasser les activités connexes).
- **Sources** : [isc.sans.edu 33088](https://isc.sans.edu/diary/rss/33088) · [isc.sans.edu 33082](https://isc.sans.edu/diary/rss/33082)

### ART-002 – L'angle mort du navigateur : pourquoi votre CASB ne bloque pas HTTP/3 / QUIC
- **Secteur** : Tous secteurs, SaaS, IT d'entreprise
- **Acteur** : Non attribué (problème architectural CASB)
- **Tags** : casb, http3, quic, udp, tls-inspection, blind-spot
- **MITRE TTPs** : T1572, T1090, T1071.001
- **IoCs** : —
- **Analyse** : Article invité (Varun Murdula) montrant que les CASB basés sur l'inspection TCP ne couvrent pas QUIC/HTTP-3 sur UDP, permettant le contournement des blocages sans trace dans les logs.
- **Recommandations** : Tester QUIC/HTTP-3 via pages de test ; compléter par filtrage DNS, SNI et blocage applicatif au pare-feu ; journaliser les flux QUIC non inspectés ; demander un roadmap aux éditeurs.
- **Playbook** : Préparation (cartographier les egress points et la couverture QUIC), Détection (journaliser UDP/443, détecter HTTP/3 via JA3/JA4), Confinement (désactiver HTTP-3 dans les navigateurs managés, bloquer QUIC au pare-feu), Post-incident (auditer les flux exfiltrés, mettre à jour la politique CASB), Chasse (chasser les flux UDP/443 longs).
- **Sources** : [isc.sans.edu 33084](https://isc.sans.edu/diary/rss/33084)

### ART-003 – Guide SOC pour le triage des alertes (ANY.RUN)
- **Secteur** : Tous secteurs
- **Acteur** : Non applicable (guide défensif)
- **Tags** : soc, triage, alert-handling, process
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : Méthodologie de triage pour SOC : enrichissement automatisé, priorisation, collecte précoce d'artefacts, documentation reproductible.
- **Recommandations** : Standardiser les runbooks ; automatiser l'enrichissement ; utiliser les sandbox interactives ; capitaliser dans une base de playbooks.
- **Playbook** : Préparation (SLA par sévérité), Détection (centralisation et scoring), Confinement (décision FP/surveillance/confinement), Post-incident (rapport standardisé), Chasse (nouvelles hypothèses).
- **Sources** : [any.run](https://any.run/cybersecurity-blog/triage-analyst-guide/)

### ART-004 – Linux hacking partie 11 : détournement GOT/PLT
- **Secteur** : Linux, Software Security
- **Acteur** : Non applicable (article pédagogique)
- **Tags** : linux, binary-exploitation, got-plt, hijacking, reverse-engineering
- **MITRE TTPs** : T1574.006
- **IoCs** : —
- **Analyse** : Détournement des entrées GOT/PLT sous Linux pour intercepter l'appel à des fonctions libc. Technique classique de red team / développement d'exploit.
- **Recommandations** : Activer Full RELRO et PIE ; surveiller les écritures GOT ; tester via checksec / hardening-check.
- **Playbook** : Préparation (builds -Wl,-z,relro,-z,now + PIE), Détection (auditd, eBPF, EDR Linux), Confinement (isoler, capturer mémoire, geler processus), Post-incident (analyser binaire, vérifier persistance), Chasse (analyses mémoire sur hôtes critiques).
- **Sources** : [cocomelonc](https://cocomelonc.github.io/linux/2026/06/17/linux-hacking-11.html)

### ART-005 – StealerLens (Flare) : analyse forensique des logs infostealers
- **Secteur** : Tous secteurs
- **Acteur** : Opérateurs InfoStealers (multi-acteurs)
- **Tags** : infostealer, stealer-logs, forensics, llm, flare, firstcon
- **MITRE TTPs** : T1555.003, T1539, T1078.004
- **IoCs** : —
- **Analyse** : StealerLens automatise via LLM l'extraction de la source d'infection, du vecteur, de l'identité du malware et d'artefacts spécifiques depuis des dumps de stealers.
- **Recommandations** : Intégrer StealerLens au DFIR ; vérifier la présence des domaines/credentials dans les dumps ; rotation cookies/sessions et AMR ; surveiller les marchés de logs.
- **Playbook** : Préparation (cartographier exposés, surveiller marchés), Détection (collecter via Flare, corréler), Confinement (déconnecter sessions, révoquer tokens), Post-incident (documenter chaîne, notifier), Chasse (empreintes de stealers, croisement avec sources).
- **Sources** : [flare.io](https://flare.io/learn/resources/blog/stealerlens-stealer-log-analysis)

### ART-006 – Paysage des risques de surveillance numérique étatique (Recorded Future)
- **Secteur** : Gouvernement, défense, télécom, OIV
- **Acteur** : Acteurs étatiques (multi-acteurs)
- **Tags** : state-surveillance, threat-landscape, recorded-future
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : Synthèse des opérations de surveillance étatique : marché NSO/Intellexa/Candiru/Paragon, OSINT offensives, supply chain et interception opérateur.
- **Recommandations** : Évaluer l'exposition des profils à haut risque ; durcir les mobiles (Lockdown iOS, GrapheneOS) ; auditer les fournisseurs de surveillance commerciale ; surveiller les IoC APT.
- **Playbook** : Préparation (identifier profils à risque, politiques voyage), Détection (MDM/EDR mobiles, Pegasus/Predator/Graphite), Confinement (révoquer appareil, isoler), Post-incident (analyse Citizen Lab/Amnesty, notification CNI), Chasse (rétro-traces sur appareils).
- **Sources** : [recordedfuture](https://www.recordedfuture.com/research/state-digital-surveillance-risk-landscape)

### ART-007 – Détection des abus d'outils RMM (Red Canary)
- **Secteur** : Tous secteurs, MSP, PME, IT
- **Acteur** : Groupes ransomware et acteurs financiers (multi-acteurs)
- **Tags** : rmm, living-off-the-land, net-support-manager, screenconnect, logmein, red-canary, detection
- **MITRE TTPs** : T1219, T1059, T1078.002, T1543, T1105, T1027
- **IoCs** : session[.]in (domain, Medium), client32.exe (process, Medium)
- **Analyse** : Recrudescence de l'abus d'outils RMM légitimes (ScreenConnect, LogMeIn Resolve, PDQ Connect, NetSupport Manager, etc.) avec empilement redondant pour survivre à une remédiation partielle.
- **Recommandations** : Maintenir un inventaire RMM autorisés + AppLocker/WDAC ; détecter les installations silencieuses ; règles EDR sur ports C2 RMM (ex : 593 NetSupport) ; journaliser les exécutions PowerShell depuis RMM.
- **Playbook** : Préparation (référentiel RMM approuvés, durcir installations), Détection (binaires RMM hors contexte IT, processus enfants, DNS C2), Confinement (désinstaller agents non autorisés, isoler, bloquer C2), Post-incident (chasse élargie, nettoyer persistance, communiquer avec MSP), Chasse (chemins non standards, ports C2, certificats auto-signés).
- **Sources** : [redcanary](https://redcanary.com/blog/security-operations/rmm-detection/)

### ART-008 – WasmForge : builder WASM pour Sliver C2
- **Secteur** : Red team
- **Acteur** : Non applicable (publication communauté redteam)
- **Tags** : red-team, tooling, wasm, sliver, c2
- **MITRE TTPs** : T1027.013, T1620
- **IoCs** : —
- **Analyse** : Compile du code Go/C# en WebAssembly pour rendre les charges utiles difficiles à détecter, compatible avec le C2 Sliver.
- **Recommandations** : Surveiller les runtimes WASM (Wasmer, Wasmtime) ; détecter les .wasm non signés ; règles EDR sur création de process wasmer/wasmtime.
- **Playbook** : Préparation (cartographier runtimes WASM autorisés), Détection (process wasmer/wasmtime non signés, modules .wasm depuis Internet), Confinement (isoler, capturer module, bloquer C2 Sliver), Post-incident (analyser module, nettoyer persistance), Chasse (artefacts WASM résiduels).
- **Sources** : [reddit WASMForge](https://www.reddit.com/r/redteamsec/comments/1u8b73j/wasmforge_a_builder_for_virtualizing_your_go_or_c/)

### ART-009 – BroVan : émulateur Windows/Linux pour RE
- **Secteur** : Red team, RE
- **Acteur** : Non applicable (publication communauté redteam)
- **Tags** : reverse-engineering, emulator, windows, linux, tooling
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : Outil libre émulant simultanément les binaires Windows et Linux pour faciliter la rétro-ingénierie multiplateforme.
- **Recommandations** : Utiliser dans des environnements isolés ; ne pas exécuter de binaires non approuvés hors air-gap ; documenter les IoC dans la base CTI.
- **Playbook** : Préparation (air-gap avec émulateurs), Détection (N/A), Confinement (restreindre aux analystes habilités), Post-incident (capitaliser IoC/TTPs), Chasse (tester anti-sandbox/anti-debug).
- **Sources** : [reddit BroVan](https://www.reddit.com/r/redteamsec/comments/1u84s19/brovan_windows_linux_emulator_for_reverse/)

### ART-010 – Politiques QoS pour restreindre le trafic EDR
- **Secteur** : Tous secteurs
- **Acteur** : Adversaires ciblant EDR (multi-acteurs)
- **Tags** : edr-evasion, qos, windows, red-team
- **MITRE TTPs** : T1562.010, T1070, T1090
- **IoCs** : —
- **Analyse** : Manipulation de règles QoS Windows pour limiter la bande passante des agents EDR et perturber la télémétrie.
- **Recommandations** : Détecter les modifications QoS (gpupdate, netsh qos, MMC QoS) ; auditer régulièrement les GPO réseau ; superviser la santé des agents EDR.
- **Playbook** : Préparation (documenter QoS de référence, intégrer supervision EDR), Détection (alertes sur modifications QoS), Confinement (restaurer QoS, isoler hôte, vérifier EDR), Post-incident (protéger GPO, bloquer netsh qos pour non-admins), Chasse (logs GPO modifiés, indicateurs EDR compromis).
- **Sources** : [reddit QoS](https://www.reddit.com/r/redteamsec/comments/1u85euf/qos_policies_to_restrict_edr_traffic_and/)

### ART-011 – LLMjacking évolué (Sysdig)
- **Secteur** : Cloud, AI, SaaS
- **Acteur** : Acteurs opportunistes LLMjacking
- **Tags** : llmjacking, ai-compute, offensive-agents, cloud, credential-theft
- **MITRE TTPs** : T1078, T1550.001, T1496
- **IoCs** : —
- **Analyse** : Vol d'identifiants cloud pour exécuter des modèles LLM/GPU coûteux et orchestrer des agents IA offensifs (phishing automatisé, identification de vulnérabilités, exfiltration).
- **Recommandations** : Surveiller les appels API LLM inhabituels ; alertes financières cloud ; VPC endpoints + SCP/AWS Organizations ; MFA + rotation courte des clés API.
- **Playbook** : Préparation (inventaire comptes cloud AI, budget alertes), Détection (volume horaire, modèles inhabituels, géographie), Confinement (révoquer clés, isoler workloads, désactiver accès LLM), Post-incident (auditer historique d'appels, durcir la gestion d'identifiants), Chasse (rôles/credentials compromis, logs API).
- **Sources** : [sysdig](https://webflow.sysdig.com/blog/llmjacking-evolved-attackers-are-using-stolen-ai-compute-to-build-offensive-agentic-tools)

### ART-012 – Strain GitHub agentique : 5 dépôts de gouvernance
- **Secteur** : Software Development, AI
- **Acteur** : Non applicable (post communautaire)
- **Tags** : github, agent-infrastructure, ai, governance
- **MITRE TTPs** : —
- **IoCs** : implicator[.]ai (domain, Low)
- **Analyse** : Mise en avant de 5 dépôts pour ajouter des contrôles (scan, audit, gouvernance) autour d'agents IA déployés à l'échelle.
- **Recommandations** : Évaluer les scanners de sécurité pour agents IA ; mettre en place un ledger d'usage ; standardiser un gateway de gouvernance.
- **Playbook** : Préparation (sélectionner outils de gouvernance), Détection (intégrer scanners au CI/CD), Confinement (bloquer déploiements non conformes), Post-incident (auditer le ledger, ajuster seuils), Chasse (graphe de mémoire pour comportements atypiques).
- **Sources** : [implicator](https://www.implicator.ai/repo-radar-5-github-projects-worth-your-week-8/) · [mastodon schuler](https://mastodon.social/@schuler/116769409000961735)

### ART-013 – Bluekit – Phishing-as-a-Service
- **Secteur** : Tous secteurs
- **Acteur** : Bluekit (PhaaS)
- **Tags** : phaas, phishing, bluekit, otx, unverified
- **MITRE TTPs** : T1566, T1583.001
- **IoCs** : —
- **Analyse** : Pulse OTX signalant la disponibilité d'une plateforme Bluekit classée PhaaS : templates, hébergement, kits clé en main. Données préliminaires à vérifier.
- **Recommandations** : Surveiller domaines/templates Bluekit ; renforcer la formation anti-phishing ; durcir MFA et détection.
- **Playbook** : Préparation (veille PhaaS, intégrer IoC), Détection (regex/signatures templates), Confinement (quarantaine emails, bloquer domaines, désactiver comptes compromis), Post-incident (communiquer, réinitialiser credentials), Chasse (rétro-IoC Bluekit dans logs).
- **Sources** : [otx alienvault](https://otx.alienvault.com/pulse/6a337860ca771cf92e8adfa6) · [social.raytec](https://social.raytec.co/@techbot/116769367156251346)

### ART-014 – APT-Q-27 – nouvel échantillon identifié
- **Secteur** : Tous secteurs
- **Acteur** : APT-Q-27
- **Tags** : apt, apt-q-27, malware-sample, otx, unverified
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : Pulse OTX signalant un nouvel échantillon attribué à APT-Q-27 (origine chinoise présumée). Données préliminaires.
- **Recommandations** : Différer et analyser dans un environnement isolé ; diffuser les IoC émergents ; suivre les publications de vendors pour corroborer.
- **Playbook** : Préparation (lab d'analyse APT dédié, former à la RE), Détection (signatures/IoC du sample via EDR), Confinement (isoler hôte, bloquer C2, désactiver comptes), Post-incident (documenter chaîne, partager CTI), Chasse (TTPs d'APT-Q-27).
- **Sources** : [otx alienvault](https://otx.alienvault.com/pulse/6a337898ca771cf92e8adfa7) · [social.raytec](https://social.raytec.co/@techbot/116769367087381981)

### ART-015 – ASN AS14061 (Singapour)
- **Secteur** : Tous secteurs
- **Acteur** : Non attribué
- **Tags** : asn, shodan, infrastructure, singapore
- **MITRE TTPs** : —
- **IoCs** : AS14061 (ip, Low)
- **Analyse** : Ajout d'un ASN Singapourien (AS14061) à un outil de veille Shodan. Potentiel hébergeur de C2/infrastructure malveillante.
- **Recommandations** : Vérifier si l'ASN héberge des services exposés non maîtrisés ; ajouter le bloc IP aux listes de surveillance.
- **Playbook** : Préparation (cartographier ASN à risque), Détection (trafic sortant vers AS14061), Confinement (bloquer au pare-feu si non requis), Post-incident (documenter le contexte ASN), Chasse (pivoter sur plages IP).
- **Sources** : [infosec.exchange shodansafari](https://infosec.exchange/@shodansafari/116769345526915247)

### ART-016 – Insider : accès non autorisé au dossier médical de la Princesse de Galles
- **Secteur** : Santé
- **Acteur** : Employé hospitalier indélicat
- **Tags** : data-breach, medical-records, insider-threat, royal-family
- **MITRE TTPs** : T1213, T1078.004
- **IoCs** : databreaches[.]net (domain, Low)
- **Analyse** : Poursuites contre un employé hospitalier britannique pour accès non autorisé au dossier médical de la Princesse de Galles. Cas emblématique d'insider threat.
- **Recommandations** : Auditer les accès aux dossiers VIP ; alertes sur consultations hors contexte ; former au RGPD/HIPAA.
- **Playbook** : Préparation (accès minimal, journalisation accès VIP), Détection (consultations atypiques), Confinement (suspendre l'accès, préserver preuves), Post-incident (autorités, notification personne concernée, réviser contrôles), Chasse (audit rétrospectif personnel sensible).
- **Sources** : [databreaches.net](https://databreaches.net/2026/06/17/hospital-worker-suspected-of-accessing-princess-of-waless-medical-records-to-face-prosecution/)

### ART-017 – Recrudescence des cyberattaques contre l'EdTech
- **Secteur** : Éducation, EdTech
- **Acteur** : Groupes cybercriminels (multi-acteurs)
- **Tags** : edtech, data-breach, ransomware
- **MITRE TTPs** : T1486, T1530
- **IoCs** : databreaches[.]net (domain, Low)
- **Analyse** : Hausse des incidents EdTech (ransomware-as-a-service, exfiltration de données d'élèves, revente sur marchés darkweb). Cible vulnérable en raison de la maturité cyber faible et de données sensibles (mineurs).
- **Recommandations** : Standards de sécurité fournisseurs EdTech ; chiffrement au repos et en transit ; segmentation ; sensibilisation au public scolaire.
- **Playbook** : Préparation (cartographier fournisseurs EdTech, plan de continuité pédagogique), Détection (alertes compromises dans SIEM), Confinement (isoler, désactiver interconnexion, sauvegardes immuables), Post-incident (FERPA, RGPD, CNIL, parents/élèves, autres fournisseurs), Chasse (mouvement latéral vers SI éducatifs).
- **Sources** : [databreaches.net EdTech](https://databreaches.net/2026/06/17/cybercriminals-are-targeting-edtech-data-breaches-and-ransomware-attacks-on-the-rise/?pk_campaign=feed&pk_kwd=cybercriminals-are-targeting-edtech-data-breaches-and-ransomware-attacks-on-the-rise)

### ART-018 – GitHub : ver supply-chain exploitant des signalements ignorés
- **Secteur** : Software Development, Open Source
- **Acteur** : Acteurs supply-chain (ver de chaîne d'approvisionnement)
- **Tags** : github, supply-chain, worm, vulnerability, patching
- **MITRE TTPs** : T1195.002, T1190, T1059
- **IoCs** : databreaches[.]net (domain, Low)
- **Analyse** : Des chercheurs affirment que GitHub aurait rejeté des rapports de vulnérabilité désormais exploités par un ver de chaîne d'approvisionnement se propageant via des workflows/actions mal configurés.
- **Recommandations** : Restreindre permissions GitHub Actions ; Dependabot Secret Scanning ; auditer et révoquer tokens ; runners éphémères.
- **Playbook** : Préparation (standardiser workflows, durcir permissions/secrets), Détection (alertes exécutions anormales, commits non autorisés), Confinement (révoquer tokens, suspendre workflows, isoler dépôts), Post-incident (advisory, notification mainteneurs, nettoyer forks), Chasse (IoC ver dans journaux CI).
- **Sources** : [databreaches.net worm](https://databreaches.net/2026/06/17/github-dismissed-security-reports-on-flaws-now-exploited-by-supply-chain-worm-researchers-say/?pk_campaign=feed&pk_kwd=github-dismissed-security-reports-on-flaws-now-exploited-by-supply-chain-worm-researchers-say)

### ART-019 – Compromission supply-chain npm Mastra (Microsoft)
- **Secteur** : Software Development, AI
- **Acteur** : Acteur supply-chain non attribué
- **Tags** : supply-chain, npm, mastra, postinstall, ai, microsoft
- **MITRE TTPs** : T1195.002, T1059.006, T1546
- **IoCs** : —
- **Analyse** : Paquet npm Mastra compromis : script postinstall injecté, exfiltration de variables d'environnement, tokens et déploiement d'un dropper Node.js persistant.
- **Recommandations** : Pin des versions et lockfile signé (npm ci) ; ignore-scripts=true dans .npmrc ; Socket, npm audit, OSV-Scanner ; surveiller le réseau au moment de l'installation.
- **Playbook** : Préparation (CI avec ignore-scripts, SBOM, signatures), Détection (alertes sur postinstall, requêtes sortantes inattendues pendant builds), Confinement (révoquer tokens, purger cache npm, bloquer paquet), Post-incident (analyser hôtes, notifier, advisory), Chasse (artefacts dropper Node sur postes ayant fait npm install).
- **Sources** : [microsoft mastra](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/) · [infosec.exchange bugxhunter](https://infosec.exchange/@bugxhunter/116769586435461375)

### ART-020 – Baker Distributing : brèche de données
- **Secteur** : HVAC, Distribution
- **Acteur** : Acteur non identifié (financier/crimeware)
- **Tags** : data-breach, baker-distributing, hvac, email-disclosure
- **MITRE TTPs** : T1565.002, T1530
- **IoCs** : —
- **Analyse** : Brèche en mai 2026 chez le distributeur HVAC/R américain ; publication de 116 000 e-mails uniques avec noms, adresses, téléphones, données de support. Risque élevé de phishing ciblé et d'escroqueries téléphoniques.
- **Recommandations** : Informer rapidement les clients exposés ; renforcer la détection de phishing et passerelles de messagerie ; surveiller la réutilisation des identifiants.
- **Playbook** : Préparation (plan de notification de brèche, canal client), Détection (auditer bases compromises, flux réseau sortant), Confinement (isoler bases affectées, réinitialiser accès admin), Post-incident (RGPD/CCPA, segmentation, chiffrement des bases client), Chasse (OSINT, HaveIBeenPwned, XposedOrNot).
- **Sources** : [infosec.exchange XposedOrNot](https://infosec.exchange/@XposedOrNot/116769549622474656)

### ART-021 – vxunderground / petikvx : partage de malware
- **Secteur** : Malware Research
- **Acteur** : Non applicable (anecdote communautaire)
- **Tags** : malware-sharing, vxunderground, community
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : Publication communautaire sur le partage quotidien de malware reçu d'un contact francophone (petikvx). Confirme l'écosystème informel d'échange de samples entre chercheurs.
- **Recommandations** : Continuer le partage de samples et IoC dans le respect du cadre légal ; maintenir la collaboration entre chercheurs.
- **Playbook** : Préparation (canal sécurisé PGP pour samples), Détection (N/A), Confinement (sandbox dédiée), Post-incident (capitaliser IoC dans base CTI), Chasse (N/A).
- **Sources** : [vxunderground](https://t.me/vxunderground/8967)

### ART-022 – Publications Mastodon sans contenu exploitable
- **Secteur** : Tous secteurs
- **Acteur** : Non attribué (vides informationnels)
- **Tags** : empty-feed, low-information, noise
- **MITRE TTPs** : —
- **IoCs** : —
- **Analyse** : 5 publications Mastodon (DevaOnBreaches, DysruptionHub, beyondmachines1, edwardk x2) sans texte ni observables exploitables. Bruit informationnel.
- **Recommandations** : Filtrer les publications vides avant ingestion dans la base CTI ; consulter les sources originales si nécessaire.
- **Playbook** : Préparation (filtre anti-vide dans le pipeline CTI), Détection (publications sans observables), Confinement (écartement automatique), Post-incident (auditer la qualité du flux), Chasse (N/A).
- **Sources** : [DevaOnBreaches](https://infosec.exchange/@DevaOnBreaches/116768565832607415) · [DysruptionHub](https://infosec.exchange/@DysruptionHub/116768106137521162) · [beyondmachines1](https://infosec.exchange/@beyondmachines1/116766756459144565) · [edwardk 1](https://infosec.exchange/@edwardk/116767765483727168) · [edwardk 2](https://infosec.exchange/@edwardk/116767609265594706)

### ART-023 – Attaque supply-chain Uncanny Automator Pro (WordPress)
- **Secteur** : Software Development, WordPress, e-commerce
- **Acteur** : Acteur supply-chain non attribué
- **Tags** : supply-chain, wordpress, uncanny-automator, backdoor, phishing
- **MITRE TTPs** : T1195.002, T1059, T1505.003
- **IoCs** : automatorplugin[.]com (domain, High), wordpress[.]org (domain, Low)
- **Analyse** : Compromission de l'infrastructure de distribution d'Uncanny Automator Pro (12 juin 2026) via une vulnérabilité tiers ; build 7.3.0.5 livrée 21 h à <6% des sites actifs (< milliers) avec un backdoor ; exfiltration de la base de licensing (noms, emails, clés, URLs WordPress). Risque élevé de phishing post-incident personnalisé.
- **Recommandations** : Mettre à jour vers 7.3.0.6 ; changer mots de passe et inspecter les sites ; surveiller les e-mails de phishing imitant Uncanny Owl ; principe du moindre privilège.
- **Playbook** : Préparation (inventaire extensions, durcir wp-admin, MFA, réseau séparé), Détection (Wordfence/Sucuri, processus webshell), Confinement (forcer MAJ, suspendre site, désactiver plugin, scanner backdoors), Post-incident (notifier clients, IoC, auditer accès automatorplugin.com), Chasse (tâches planifiées malveillantes, comptes admin non autorisés, entrées suspectes en base).
- **Sources** : [insicurezzadigitale](https://insicurezzadigitale.com/supply-chain-attack-su-uncanny-automator-pro-build-backdoorata-v7-3-0-5-distribuita-a-migliaia-di-siti-wordpress/)
