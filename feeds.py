"""Feed roster for PLAINTEXT.

name -> feed URL. Order here is display order on the page.
Kept in its own module so the checker and the generator can't drift.
"""

FEEDS = {
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "The Record": "https://therecord.media/feed",
    "CyberScoop": "https://cyberscoop.com/feed/",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "Troy Hunt": "https://www.troyhunt.com/rss/",
    "Rapid7 Blog": "https://www.rapid7.com/rss.xml",
    "Malwarebytes Labs": "https://www.malwarebytes.com/blog/feed/index.xml",
    "Graham Cluley": "https://grahamcluley.com/feed/",
    "WeLiveSecurity (ESET)": "https://www.welivesecurity.com/en/rss/feed/",
    "Unit 42 (Palo Alto)": "https://unit42.paloaltonetworks.com/feed/",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Zero Day Initiative": "https://www.zerodayinitiative.com/rss/published/",
    "Cisco Talos": "https://blog.talosintelligence.com/rss/",
    "Risky Business News": "https://risky.biz/feeds/risky-business-news/",
}

USER_AGENT = "Mozilla/5.0 (compatible; PlaintextReport/1.0; +https://plaintext.report)"

# Optional per-source caps, overriding the global per-source limit.
# High-volume sources can otherwise bury a source that posts twice a week.
# Editorial weighting is a taste call, so this ships empty by design; set a
# name to a number to turn it down, e.g.
#
#     SOURCE_LIMITS = {"Malwarebytes Labs": 5, "Zero Day Initiative": 5}
#
# The /cve page. Deliberately separate from the front page: these publish at
# roughly a hundred items a day and would bury actual reporting.
CVE_FEEDS = {
    "Offensive Sequence": "https://radar.offseq.com/rss.xml",
    "VulDB": "https://vuldb.com/?rss.recent",
    "Zero Day Initiative": "https://www.zerodayinitiative.com/rss/published/",
    "Exploit-DB": "https://www.exploit-db.com/rss.xml",
}

# These two link to their own interstitial pages rather than to the record.
# Where the title carries a CVE id, the link is rewritten to cve.org, which
# keeps the "headlines link straight to the publisher" promise honest and,
# because both then point at the same URL, lets the existing dedupe collapse
# the large overlap between them.
CVE_LINK_REWRITE = frozenset({"Offensive Sequence", "VulDB"})

# ZDI and Exploit-DB publish their own advisories, so their links are already
# the primary source and only need a modest cap.
CVE_SOURCE_LIMITS = {
    "Zero Day Initiative": 15,
    "Exploit-DB": 15,
}

SOURCE_LIMITS = {
    # 39 items in a 72h window, roughly 4x the next busiest source. Left
    # uncapped it takes a quarter of the page on its own.
    "The Hacker News": 10,
    # Publishes nothing for days, then dumps a batch of advisories at once.
    # The cap only bites on those burst days.
    "Zero Day Initiative": 8,
}
