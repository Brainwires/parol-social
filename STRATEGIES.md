# ParolNet Adoption & Distribution Strategy

How to take ParolNet from a codebase to a movement. This document outlines strategies for making ParolNet viral — reaching the people who need it most, in places where distribution itself is an act of resistance.

---

## 1. Grassroots Distribution

The people who need ParolNet most cannot download it from an app store. Distribution must be built into the product design.

### 1.1 No App Store Required
- **PWA (Progressive Web App)**: ParolNet runs in any browser. Share a URL, and the user has a secure messenger. No installation, no app store approval, no government takedown request to Apple or Google.
- **Sideloading (Android)**: Distribute APK files directly. Android allows installation from "unknown sources" — this is how millions of people in China and Iran already install apps.
- **F-Droid**: Publish on F-Droid, the open-source Android app store that doesn't require Google Play Services and can't be removed by government pressure.

### 1.2 Physical Distribution
- **QR Code Posters**: Print QR codes linking to the PWA on public walls, in bathrooms, in university buildings, on bus stops. The QR code leads to a URL that serves the app. If one URL is blocked, print new posters with a new URL.
- **USB Dead Drops**: Pre-load USB drives with the APK and sideloading instructions. Leave them in public places — libraries, cafes, university lounges. Include instructions in the local language.
- **Bluetooth Airdrop**: Share the APK directly between phones via Bluetooth or nearby share. This requires no internet at all — one person with the app can seed an entire community.
- **Printed Passphrase Cards**: Small cards with a ParolNet bootstrap passphrase that two people can use to connect. Hand them out at gatherings. Each card is a potential connection into the network.

### 1.3 Sneakernet & Embassy Networks
- Partner with embassy networks and international organizations to physically carry USB drives into countries with internet restrictions.
- Journalists and aid workers traveling into conflict zones can carry pre-loaded devices.
- Diaspora communities can mail USB drives to family members back home in ordinary packages.

### 1.4 Mirror Strategy
- Host the PWA on dozens of domains across different CDNs and registrars. When one is blocked, others remain.
- Publish the PWA as a Tor hidden service (.onion address) for users who already have Tor access.
- Host the APK on IPFS — content-addressed, uncensorable, and distributed.
- Use domain fronting where available: the ParolNet PWA appears to be loading from a CDN like Cloudflare or AWS, making it indistinguishable from any other website.

---

## 2. Community Building

### 2.1 Diaspora Communities
The most powerful distribution channel is people who have family in targeted countries:
- **Iranian diaspora** (estimated 4-5 million outside Iran): community organizations in Los Angeles, Toronto, London, Berlin
- **Chinese diaspora**: communities worldwide, particularly strong in Southeast Asia, North America, Australia
- **Russian-speaking diaspora**: significant populations in Germany, Israel, Baltic states, Central Asia
- **North Korean defector communities**: primarily in South Korea (~34,000+), growing networks in advocacy organizations
- **Kurdish diaspora**: large communities in Germany, Sweden, Iraq (Kurdistan Region)
- **Myanmar diaspora**: growing communities in Thailand, India, Malaysia since 2021 coup

Engage these communities through:
- Cultural organizations and community centers
- Diaspora media outlets (Persian-language satellite TV, Chinese-language social media)
- Religious institutions that maintain cross-border connections
- Existing activist networks within these communities

### 2.2 Journalist & Press Freedom Networks
- **Reporters Without Borders (RSF)**: operate in 130 countries, maintain networks of journalists in restrictive environments
- **Committee to Protect Journalists (CPJ)**: direct connections to journalists under threat
- **International Press Institute (IPI)**: network across Europe and Asia
- **Local press freedom organizations**: in every target country, there are underground or semi-legal journalist networks

Offer ParolNet as a tool specifically for source protection. A journalist using ParolNet to communicate with sources leaves no metadata trail — no phone records, no email headers, no server logs.

### 2.3 Human Rights & Civil Society
- **Amnesty International**: field offices in 70+ countries, direct contact with at-risk individuals
- **Human Rights Watch**: extensive research networks in every region
- **Access Now**: specifically focused on digital rights, runs a digital security helpline
- **Electronic Frontier Foundation (EFF)**: strong technical community, can validate and promote
- **Front Line Defenders**: protects human rights defenders, provides security training
- **Citizen Lab**: University of Toronto research lab that studies internet censorship — validation from them is gold

### 2.4 Student Networks
Universities are often the birthplace of resistance movements:
- Partner with student organizations in universities with large international student populations
- Computer science departments can contribute to development and auditing
- Student activist groups in target countries are often technically sophisticated and well-connected

---

## 3. Technical Evangelism

### 3.1 Security Conference Talks
Present at conferences where the security research community gathers:
- **DEF CON** (Las Vegas): largest hacker conference, 30,000+ attendees. Present in the Crypto & Privacy Village.
- **Chaos Communication Congress (CCC)** (Germany): European hacker community, strong privacy focus, well-connected to activist networks
- **RightsCon** (rotating): the world's leading summit on human rights in the digital age
- **USENIX Security**: academic security conference, lends credibility
- **PETS (Privacy Enhancing Technologies Symposium)**: directly relevant audience
- **HOPE (Hackers On Planet Earth)**: New York, strong activism focus

### 3.2 Open Source Contributor Onboarding
Make it easy for developers to contribute:
- Clear CONTRIBUTING.md with setup instructions, coding standards, and "good first issue" labels
- Modular architecture means contributors can work on one crate without understanding the whole system
- Security-focused issues attract skilled developers who care about the mission
- Mentorship program for developers from target countries
- Document the architecture so deeply that anyone can audit it

### 3.3 Academic Collaboration
- Publish the protocol specifications as academic papers
- Collaborate with cryptography researchers on formal verification
- Engage with university labs working on censorship circumvention (Citizen Lab, OONI, ICLab)
- Offer ParolNet as a platform for graduate student research

---

## 4. Media & Awareness

### 4.1 Narrative Strategy
ParolNet's story is compelling because it's not abstract — it's about real people:
- **Lead with stories, not technology**: "A journalist in Iran can now communicate with sources without either of them risking arrest" is more powerful than "we use X3DH key agreement with Double Ratchet"
- **Frame it as a human rights tool**: not a "hacker tool" or "dark web app" — this is the digital equivalent of a sealed letter
- **Emphasize what makes it different**: "It looks like you're browsing the web. Because to your ISP, you are."

### 4.2 Press Strategy
- Op-eds in major publications timed to censorship events (internet shutdowns, journalist arrests)
- Technical deep-dives in security-focused outlets (Ars Technica, The Register, Wired)
- Profiles in human rights publications (The Intercept, Al Jazeera English, BBC Persian)
- Academic press for the cryptographic innovations

### 4.3 Social Media
- Focus on platforms used by diaspora communities: Twitter/X, Telegram channels, WeChat (carefully), Signal groups
- Create content in target languages — Persian, Chinese, Russian, Arabic, Korean, Turkish, Kurdish
- Short explainer videos: "How to connect with ParolNet in 60 seconds"
- Testimonial campaigns from users in safe positions (diaspora, researchers, journalists in free countries)

### 4.4 Documentation as Advocacy
- Publish a public threat model: "This is exactly what we protect against, and this is what we don't" — radical transparency builds trust
- Publish censorship circumvention case studies: how ParolNet bypasses specific DPI systems used by specific governments
- Maintain a "censorship weather report": real-time status of internet freedom in target countries, showing where ParolNet is most needed

---

## 5. Network Effects

ParolNet gets stronger with every user. Make this visible and rewarding.

### 5.1 Relay Volunteering
- Anyone can run a ParolNet relay node — it's just a server that forwards encrypted traffic
- Make relay setup trivially easy: one Docker command, one cloud provider click
- Relays cost bandwidth but not much compute. A $5/month VPS can serve hundreds of users.
- Show relay operators their impact: "Your relay has forwarded 50,000 messages this month"
- Relay diversity is security: the more relays in different countries and jurisdictions, the harder it is to compromise all three hops

### 5.2 Mesh Density
- In mesh mode (no internet), more nearby devices = better message delivery
- Visualize mesh density: "There are 47 ParolNet nodes within range right now"
- When internet is shut down, mesh becomes the network. This happened in protests in Hong Kong, Iran, Myanmar. Be ready.

### 5.3 Bootstrap Virality
- Connecting two people requires scanning a QR code or sharing a passphrase
- This is inherently an in-person, high-trust interaction
- Each successful bootstrap is a strong social bond — these users will recruit others
- Design the QR exchange to be fast and pleasant: scan, confirm, done in 10 seconds

### 5.4 Community Relays
- Communities can run their own relay infrastructure, creating regional networks
- Mosques, churches, universities, activist houses can host relays
- "Community relay" concept: a relay run by a trusted community organization
- This creates local ownership and reduces dependence on any external entity

---

## 6. Trust Building

In the target environments, trust is everything. Users risk their lives. The tool must be beyond reproach.

### 6.1 Reproducible Builds
- Every release must be reproducibly buildable: anyone can compile the source code and verify that the binary matches the official release
- This proves that no backdoor was inserted between source code and binary
- Document the build process so thoroughly that non-experts can verify

### 6.2 Public Security Audits
- Commission at least one professional security audit before any public release
- Publish the full audit report, including all findings and remediations
- Follow up with annual audits as the codebase evolves
- Engage multiple audit firms from different jurisdictions to prevent single-point compromise

### 6.3 Transparency Reports
- Publish quarterly transparency reports:
  - Network statistics (relay count, message volume — aggregate only)
  - Any legal requests received and how they were handled
  - Security incidents and responses
  - Development roadmap progress

### 6.4 No Corporate Ownership
- ParolNet must never be owned by a company that can be compelled, acquired, or shut down
- Organizational models: non-profit foundation, open-source collective, or fully decentralized governance
- No venture capital — VC investors eventually need returns, which creates pressure to monetize or compromise
- Governance should be transparent and community-driven

### 6.5 Threat Model Honesty
- Be explicit about what ParolNet does NOT protect against
- Document known limitations prominently
- Never claim to be "unbreakable" or "NSA-proof" — overclaiming destroys trust
- When vulnerabilities are found, disclose them promptly with clear mitigation guidance

---

## 7. Funding Strategy

### 7.1 Grants (Primary)
Organizations that fund censorship circumvention and digital rights tools:
- **Open Technology Fund (OTF)**: the primary funder of internet freedom tools (funded Tor, Signal, Tails). Annual budget ~$20M. Apply for Internet Freedom Fund.
- **NLnet Foundation**: European foundation funding open-source internet infrastructure. Funds up to EUR 50K per project through the NGI program.
- **Mozilla Foundation**: MOSS (Mozilla Open Source Support) awards up to $250K for open-source projects
- **Ford Foundation**: funds technology for social justice
- **Omidyar Network**: digital rights focus
- **Prototype Fund** (Germany): up to EUR 47.5K for open-source civic tech

### 7.2 Donations
- Accept cryptocurrency donations (Bitcoin, Monero) — donors can contribute anonymously
- OpenCollective or GitHub Sponsors for transparent, public donation tracking
- Never accept donations from governments of target countries or their allies — this would destroy trust

### 7.3 What NOT to Do
- No venture capital
- No advertising or data monetization (this would be antithetical to the mission)
- No government contracts (creates conflicts of interest)
- No exclusive partnerships with any single organization
- No "premium tier" — all security features must be available to all users

---

## 8. Localization

### 8.1 Community-Driven Translation
- All UI text, documentation, and help content must be available in target languages
- Priority languages: Persian (Farsi), Chinese (Simplified), Russian, Arabic, Kurdish, Korean, Turkish, Azerbaijani, Burmese, Belarusian
- Translations should be done by native speakers from the communities, not by automated tools
- Diaspora communities are the best source of translators — they understand both the language and the context

### 8.2 Regional Ambassadors
- Recruit trusted individuals in each target region to serve as community contacts
- Ambassadors help with: translation review, local distribution, user support, feedback collection
- Ambassadors should be volunteers who believe in the mission — never paid agents
- Protect ambassador identities — they may be at risk

### 8.3 Cultural Adaptation
- UI design should accommodate RTL (right-to-left) languages: Arabic, Persian, Kurdish
- QR code instructions should use culturally appropriate imagery
- Decoy mode should disguise as apps that are normal in the target culture (calculator, prayer times, weather)
- Error messages and help text should be written simply — not all users are technically sophisticated

---

## 9. Maintaining Network Integrity

### 9.1 Federated Trust Model
ParolNet uses a federated authority system to prevent network infiltration:
- When a network is created, 2-3 trusted people each receive an **authority key** (Ed25519 keypair)
- Only relays **endorsed by a threshold of authorities** (e.g. 2-of-3) are accepted by the app
- Authority public keys are baked into the PWA at build time — users cannot be tricked into connecting to rogue relays
- A state actor cannot spin up fake relays to harvest user IPs without compromising multiple authority key holders

### 9.2 Sybil Attack Prevention
- Without authority endorsement, a relay is invisible to the network
- Endorsements expire — compromised or abandoned relays are automatically dropped
- Each endorsement is cryptographically signed and verified by every client
- The threshold requirement means a single compromised authority cannot inject malicious relays

### 9.3 Relay Operator Vetting
- Authority key holders are the gatekeepers — they must personally verify relay operators before endorsing
- Endorsements should include expiry dates (e.g. 365 days) to force periodic re-vetting
- If a relay operator is compromised, simply let their endorsement expire — no app update needed
- Keep authority key holders in different jurisdictions when possible — harder to coerce all of them simultaneously

### 9.4 Network Identity
- Each network has a deterministic identity: `SHA-256(sorted authority pubkeys)`
- Users can verify they're on the correct network by comparing network IDs
- Different communities can run entirely separate ParolNet networks with their own authority keys
- Networks are isolated by design — a compromised network cannot affect other networks

### 9.5 Key Compromise Response
- If one authority key is lost or compromised: the network still functions (2-of-3 threshold)
- If two keys are compromised: rebuild the network with new keys, users export/reimport their data
- Authority private keys must NEVER be on relay servers, in the PWA, or on internet-connected machines used for other purposes
- See [STARTUP-GUIDE.md](STARTUP-GUIDE.md) for key management procedures

### 9.6 Relay-to-Relay Resilience
- Every relay syncs the full directory with every other relay
- If all but one relay goes down, the surviving relay has the complete directory
- Clients cache the relay directory locally — they can reconnect even after extended outages
- Bootstrap relay addresses are bundled in the PWA for first-launch discovery
- Any single relay alive = entire network reachable

---

## 10. Resilience Against Takedown

### 9.1 No Single Point of Failure
- No central server to shut down
- No company to issue a legal order against
- No app store listing to remove
- No domain to seize (multiple mirrors, .onion, IPFS)
- No developer to arrest (distributed, pseudonymous core team)

### 9.2 Anti-Censorship Distribution
- If a government blocks the PWA domain, new domains can be deployed in minutes
- QR codes with new URLs can be printed and distributed physically
- The app can be shared phone-to-phone via Bluetooth, completely offline
- The source code is on GitHub, GitLab, Codeberg, and self-hosted mirrors simultaneously
- Archived on the Wayback Machine and Software Heritage

### 9.3 Protocol Resilience
- If DPI systems learn to detect ParolNet traffic (despite camouflage), the pluggable transport system allows switching to new transport methods without changing the app
- TLS fingerprint profiles can be updated without a software release
- New relay nodes can be spun up anywhere in the world in minutes
- The gossip protocol ensures the relay directory is distributed — there is no directory server to take down

### 9.4 Legal Resilience
- MIT/Apache-2.0 license means the code is legally free to use, modify, and distribute worldwide
- No patents, no proprietary components, no legal encumbrances
- The project should be incorporated (if at all) in a jurisdiction with strong free speech protections
- Legal defense fund for contributors who face legal threats

---

## 11. Metrics for Success

How do we know if ParolNet is working?

| Metric | Target (Year 1) | Target (Year 3) |
|--------|-----------------|-----------------|
| Active relay nodes | 100+ | 1,000+ |
| Countries with users | 10+ | 50+ |
| Messages per day | 10,000+ | 1,000,000+ |
| Languages supported | 8 | 20+ |
| Security audits completed | 1 | 3+ |
| Contributor community | 20+ devs | 100+ devs |
| Internet shutdown survivability | Mesh proof-of-concept | Documented real-world use |
| Government censorship bypasses | 1+ documented | Routine, documented |

The ultimate metric is simple: **Can a journalist in Tehran safely communicate with a source?** Everything else is a means to that end.

---

## Call to Action

If you're reading this and you can help — contribute code, run a relay, translate documentation, fund development, or simply tell people about ParolNet — you are directly supporting the fundamental right to private communication for millions of people who don't have it.

The technology is the easy part. Building trust, reaching users, and sustaining the network is the real challenge. That takes a community.

Start here:
- Run a relay: `docker run parolnet/relay` (coming soon)
- Contribute: See [CONTRIBUTING.md](CONTRIBUTING.md)
- Donate: See funding page (coming soon)
- Translate: Open an issue with your language
- Spread the word: Share this project with someone who needs it
