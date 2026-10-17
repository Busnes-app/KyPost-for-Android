package org.kysecurity.mail

import okhttp3.Call
import okhttp3.EventListener
import okhttp3.Request
import okio.Timeout
import java.util.concurrent.ConcurrentHashMap
import kotlin.reflect.KClass

/** Base for a [Call] that never touches the network: a refusal, or a test fake.
 *
 *  Tags behave as on OkHttp's own calls: seeded from [request]'s tags, growing as they are computed.
 *  No events are ever emitted, so an added [EventListener] has nothing to hear. */
internal abstract class OfflineCall(private val request: Request) : Call {
    private val computedTags = ConcurrentHashMap<KClass<*>, Any>()

    override fun request(): Request = request
    override fun timeout(): Timeout = Timeout.NONE
    override fun addEventListener(eventListener: EventListener) = Unit

    override fun <T : Any> tag(type: KClass<T>): T? = type.java.cast(computedTags[type] ?: request.tag(type))
    override fun <T> tag(type: Class<out T>): T? = type.cast(computedTags[type.kotlin] ?: request.tag(type))
    override fun <T : Any> tag(type: KClass<T>, computeIfAbsent: () -> T): T =
        tag(type) ?: type.java.cast(computedTags.computeIfAbsent(type) { computeIfAbsent() })
    override fun <T : Any> tag(type: Class<T>, computeIfAbsent: () -> T): T = tag(type.kotlin, computeIfAbsent)
}
