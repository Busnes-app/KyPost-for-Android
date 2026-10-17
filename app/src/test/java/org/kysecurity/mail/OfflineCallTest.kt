package org.kysecurity.mail

import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class OfflineCallTest {

    private class TestCall(request: Request) : OfflineCall(request) {
        override fun execute(): Response = throw UnsupportedOperationException()
        override fun enqueue(responseCallback: Callback) = Unit
        override fun cancel() = Unit
        override fun isExecuted() = false
        override fun isCanceled() = false
        override fun clone() = this
    }

    private val request = Request.Builder().url("https://relay.example/").tag(String::class.java, "seed").build()

    @Test
    fun tagsAreSeededFromTheRequest() {
        val call = TestCall(request)
        assertEquals("seed", call.tag(String::class))
        assertEquals("seed", call.tag(String::class.java))
        assertEquals("seed", call.tag(String::class) { "computed" })
        assertNull(call.tag(Int::class))
    }

    @Test
    fun aComputedTagIsStoredAndNotRecomputed() {
        val call = TestCall(request)
        val first = call.tag(StringBuilder::class) { StringBuilder("a") }
        assertSame(first, call.tag(StringBuilder::class.java) { StringBuilder("b") })
        assertSame(first, call.tag(StringBuilder::class))
        assertNull(request.tag(StringBuilder::class))
    }
}
