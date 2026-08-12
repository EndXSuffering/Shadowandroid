package dev.shadow.firewall.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UidNamesTest {

    @Test
    fun `names the android service uids that actually open sockets`() {
        assertEquals("Android DNS resolver", UidNames.systemService(1051))
        assertEquals("Android system", UidNames.systemService(1000))
        assertEquals("Telephony", UidNames.systemService(1001))
        assertEquals("Network stack", UidNames.systemService(1073))
        assertEquals("IPv6 translation (clat)", UidNames.systemService(1029))
    }

    @Test
    fun `an unlisted service uid is not guessed at`() {
        assertNull(UidNames.systemService(1234))
        assertEquals("Android service (uid 1234)", UidNames.describe(1234))
    }

    @Test
    fun `an ordinary app uid is in the application range`() {
        assertTrue(UidNames.isApplication(10123))
        assertFalse(UidNames.isApplication(1051))
        assertFalse(UidNames.isApplication(99123))
    }

    @Test
    fun `a sandboxed renderer is recognised rather than called unknown`() {
        assertTrue(UidNames.isIsolated(99012))
        assertTrue(UidNames.isIsolated(90001))
        assertEquals("Sandboxed process (uid 99012)", UidNames.describe(99012))
    }

    @Test
    fun `a work profile uid resolves to the same app id and names its profile`() {
        val personal = 10123
        val work = UidNames.PER_USER_RANGE + personal

        assertEquals(0, UidNames.userId(personal))
        assertEquals(1, UidNames.userId(work))
        assertEquals(personal, UidNames.appId(work))
        assertTrue(UidNames.isApplication(work), "a work-profile app is still an app")
        assertEquals("Removed app (uid 10123) · profile 1", UidNames.describe(work))
    }

    @Test
    fun `a service uid in a second profile keeps its name`() {
        assertEquals("Android DNS resolver", UidNames.systemService(UidNames.PER_USER_RANGE + 1051))
        assertEquals(
            "Android DNS resolver · profile 1",
            UidNames.describe(UidNames.PER_USER_RANGE + 1051),
        )
    }

    @Test
    fun `a failed lookup is described as unattributed, not as an app`() {
        assertEquals("Unattributed connection", UidNames.describe(UidNames.UNAVAILABLE))
        assertEquals("Unattributed connection", UidNames.describe(-1))
        assertNotNull(UidNames.unattributedExplanation(-1))
    }

    @Test
    fun `a known uid needs no unattributed explanation`() {
        assertNull(UidNames.unattributedExplanation(10123))
        assertNull(UidNames.unattributedExplanation(1051))
    }

    @Test
    fun `negative uids never produce a nonsense profile`() {
        assertEquals(0, UidNames.userId(-1))
        assertFalse(UidNames.describe(-1).contains("profile"))
    }
}
