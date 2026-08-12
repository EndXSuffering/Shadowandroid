package dev.shadow.firewall.rules

/** Broad grouping shown in the UI. */
enum class BlocklistCategory { ADS, MALWARE }

/**
 * A list the app knows how to subscribe to.
 *
 * @param approximateEntries roughly how many rules the list carried when this catalogue was
 *   written. Only used to warn before enabling something huge; the real count comes from the
 *   download.
 */
data class BlocklistSource(
    val id: String,
    val title: String,
    val description: String,
    val url: String,
    val category: BlocklistCategory,
    val enabledByDefault: Boolean,
    val approximateEntries: Int,
) {
    /** Lists big enough that the user should be warned before switching them on. */
    val isHeavy: Boolean get() = approximateEntries > 500_000
}

/**
 * The built-in list catalogue.
 *
 * Everything here is served from the AdGuard hostlists registry, which mirrors the upstream
 * lists and republishes them in one consistent format at stable URLs. Pointing at a dozen
 * different maintainers' own hosting would mean a dozen different formats, uptime records and
 * URL-rename risks; the registry is a single well-maintained indirection.
 *
 * StevenBlack's unified hosts file is the exception, taken from its own repository because it
 * is the canonical hosts-format list and exercises that parser path.
 */
object BlocklistCatalog {

    private const val REGISTRY =
        "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets"

    val sources: List<BlocklistSource> = listOf(
        BlocklistSource(
            id = "adguard_dns",
            title = "AdGuard DNS filter",
            description = "The main ad and tracker list. A good default on its own.",
            url = "$REGISTRY/filter_1.txt",
            category = BlocklistCategory.ADS,
            enabledByDefault = true,
            approximateEntries = 154_000,
        ),
        BlocklistSource(
            id = "adguard_popups",
            title = "AdGuard popup hosts",
            description = "Hosts that exist only to serve pop-ups and pop-unders.",
            url = "$REGISTRY/filter_59.txt",
            category = BlocklistCategory.ADS,
            enabledByDefault = false,
            approximateEntries = 1_000,
        ),
        BlocklistSource(
            id = "stevenblack",
            title = "StevenBlack unified hosts",
            description = "Long-standing hosts file covering ads and malware. " +
                "Overlaps the AdGuard list heavily, so it is off by default.",
            url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            category = BlocklistCategory.ADS,
            enabledByDefault = false,
            approximateEntries = 98_000,
        ),
        BlocklistSource(
            id = "phishing_army",
            title = "Phishing Army",
            description = "Domains actively used in phishing campaigns.",
            url = "$REGISTRY/filter_18.txt",
            category = BlocklistCategory.MALWARE,
            enabledByDefault = true,
            approximateEntries = 156_000,
        ),
        BlocklistSource(
            id = "shadowwhisperer_malware",
            title = "ShadowWhisperer's malware list",
            description = "Malware distribution and command-and-control hosts.",
            url = "$REGISTRY/filter_42.txt",
            category = BlocklistCategory.MALWARE,
            enabledByDefault = true,
            approximateEntries = 43_000,
        ),
        BlocklistSource(
            id = "dandelion_malware",
            title = "Dandelion Sprout's anti-malware list",
            description = "Curated malware hosts, including some raw IP addresses.",
            url = "$REGISTRY/filter_12.txt",
            category = BlocklistCategory.MALWARE,
            enabledByDefault = true,
            approximateEntries = 12_000,
        ),
        BlocklistSource(
            id = "scam_blocklist",
            title = "Scam blocklist",
            description = "Small, high-confidence list of scam and fraud sites.",
            url = "$REGISTRY/filter_10.txt",
            category = BlocklistCategory.MALWARE,
            enabledByDefault = true,
            approximateEntries = 1_000,
        ),
        BlocklistSource(
            id = "hagezi_tif",
            title = "HaGeZi threat intelligence feeds",
            description = "Very broad threat feed. Over two million entries: expect a large " +
                "download and roughly 20 MB of extra memory while the tunnel runs.",
            url = "$REGISTRY/filter_44.txt",
            category = BlocklistCategory.MALWARE,
            enabledByDefault = false,
            approximateEntries = 2_200_000,
        ),
    )

    fun byId(id: String): BlocklistSource? = sources.firstOrNull { it.id == id }

    val defaultEnabledIds: Set<String> =
        sources.filter { it.enabledByDefault }.map { it.id }.toSet()
}

/** How often the background refresh runs. */
enum class UpdateFrequency(val hours: Long) {
    EVERY_6_HOURS(6),
    DAILY(24),
    WEEKLY(24 * 7),
    MANUAL(0),
    ;

    val isAutomatic: Boolean get() = this != MANUAL
}
