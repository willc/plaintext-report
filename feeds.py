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
SOURCE_LIMITS = {}
