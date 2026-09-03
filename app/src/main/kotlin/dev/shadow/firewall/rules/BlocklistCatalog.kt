package dev.shadow.firewall.rules

/** Broad grouping shown in the UI. */
enum class BlocklistCategory { ADS, TRACKING, MALWARE }

/**
 * How hard to go after trackers.
 *
 * The two levels are not a slider on the same list; they are different kinds of list. The
 * balanced set is telemetry an app can lose without noticing — vendor analytics endpoints
 * that are fire-and-forget. The strict set adds attribution, measurement and consent
 * endpoints, which some apps genuinely wait on, so it can break things.
 */
enum class TrackerProtection {
    /** No tracker lists at all. */
    OFF,

    /** Telemetry that apps discard the result of. Safe to leave on. */
    BALANCED,

    /** Everything, including endpoints apps sometimes depend on. Expect occasional breakage. */
    STRICT,
}

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
    /** The lowest tracker level at which this list switches on; null for non-tracker lists. */
    val trackerTier: TrackerProtection? = null,
    /** A list of exceptions rather than blocks; its entries override every other list. */
    val isAllowlist: Boolean = false,
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
        // --- trackers, balanced: vendor telemetry an app never checks the result of ---
        BlocklistSource(
            id = "tracking_shadowwhisperer",
            title = "ShadowWhisperer tracking list",
            description = "Analytics and telemetry endpoints. Apps discard these responses, " +
                "so losing them is not something they notice.",
            url = "$REGISTRY/filter_69.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 115_000,
            trackerTier = TrackerProtection.BALANCED,
        ),
        BlocklistSource(
            id = "tracking_peter_lowe",
            title = "Peter Lowe's list",
            description = "Small, long-maintained and conservative. Rarely the cause of a " +
                "broken app.",
            url = "$REGISTRY/filter_3.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 3_500,
            trackerTier = TrackerProtection.BALANCED,
        ),
        BlocklistSource(
            id = "tracking_oem_samsung",
            title = "Samsung telemetry",
            description = "Samsung and One UI reporting endpoints.",
            url = "$REGISTRY/filter_61.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 200,
            trackerTier = TrackerProtection.BALANCED,
        ),
        BlocklistSource(
            id = "tracking_oem_xiaomi",
            title = "Xiaomi telemetry",
            description = "Xiaomi and MIUI reporting endpoints.",
            url = "$REGISTRY/filter_60.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 350,
            trackerTier = TrackerProtection.BALANCED,
        ),
        BlocklistSource(
            id = "tracking_oem_oppo",
            title = "OPPO and Realme telemetry",
            description = "ColorOS reporting endpoints.",
            url = "$REGISTRY/filter_66.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 500,
            trackerTier = TrackerProtection.BALANCED,
        ),
        BlocklistSource(
            id = "tracking_oem_vivo",
            title = "Vivo telemetry",
            description = "Funtouch OS reporting endpoints.",
            url = "$REGISTRY/filter_65.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 230,
            trackerTier = TrackerProtection.BALANCED,
        ),

        // --- trackers, strict: broad, and known to cost you the occasional app ---
        BlocklistSource(
            id = "tracking_hagezi_pro_plus",
            title = "HaGeZi Pro++",
            description = "Aggressive. Adds attribution, measurement and consent endpoints " +
                "that some apps wait on before they will load.",
            url = "$REGISTRY/filter_51.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = false,
            approximateEntries = 250_000,
            trackerTier = TrackerProtection.STRICT,
        ),

        // --- the counterweight: exceptions that apply across every other list ---
        BlocklistSource(
            id = "allowlist_referral",
            title = "Referral and shopping exceptions",
            description = "Un-blocks the redirectors behind shopping, coupon and referral " +
                "links, which broad tracker lists otherwise break. Overrides every list.",
            url = "$REGISTRY/filter_45.txt",
            category = BlocklistCategory.TRACKING,
            enabledByDefault = true,
            approximateEntries = 900,
            trackerTier = TrackerProtection.BALANCED,
            isAllowlist = true,
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

    /** Every list that belongs to the tracker feature, at any level. */
    val trackerSources: List<BlocklistSource> = sources.filter { it.trackerTier != null }

    /** The tracker lists that should be on at [level]. */
    fun trackerIdsFor(level: TrackerProtection): Set<String> = when (level) {
        TrackerProtection.OFF -> emptySet()
        TrackerProtection.BALANCED ->
            trackerSources.filter { it.trackerTier == TrackerProtection.BALANCED }
                .map { it.id }.toSet()
        // Strict is additive: it keeps the balanced set and adds the aggressive lists.
        TrackerProtection.STRICT -> trackerSources.map { it.id }.toSet()
    }

    /**
     * Reads a level back from the enabled set, so the UI can show what is actually on rather
     * than what was last tapped. Returns null when the user has hand-picked a combination
     * that is not one of the levels.
     */
    fun trackerLevelOf(enabledIds: Set<String>): TrackerProtection? {
        val enabledTrackers = trackerSources.map { it.id }.filter { it in enabledIds }.toSet()
        return TrackerProtection.entries.firstOrNull { trackerIdsFor(it) == enabledTrackers }
    }
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
