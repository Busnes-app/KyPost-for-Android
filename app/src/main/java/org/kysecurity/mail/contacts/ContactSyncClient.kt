package org.kysecurity.mail.contacts

import org.kysecurity.mail.executeDecoding
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

sealed class ContactSyncResult {
    data class Success(val response: ContactSyncPullResponseDto) : ContactSyncResult()
    data class Unauthorized(val message: String) : ContactSyncResult()
    data class BadRequest(val message: String) : ContactSyncResult()
    data class ServiceUnavailable(val message: String) : ContactSyncResult()
    data class Retryable(val message: String) : ContactSyncResult()
}

sealed class ContactDedupeResult {
    data class Success(val report: ContactDedupeReportDto) : ContactDedupeResult()
    data class Unauthorized(val message: String) : ContactDedupeResult()
    data class BadRequest(val message: String) : ContactDedupeResult()
    data class ServiceUnavailable(val message: String) : ContactDedupeResult()
    data class Retryable(val message: String) : ContactDedupeResult()
}

private sealed class HttpMappedResult<out T> {
    data class Success<T>(val value: T) : HttpMappedResult<T>()
    data class Unauthorized(val message: String) : HttpMappedResult<Nothing>()
    data class BadRequest(val message: String) : HttpMappedResult<Nothing>()
    data class ServiceUnavailable(val message: String) : HttpMappedResult<Nothing>()
    data class Retryable(val message: String) : HttpMappedResult<Nothing>()
}

// Auth goes in X-Kypost-Device-Id/X-Kypost-Device-Secret headers, never query params or cookies.
class ContactSyncClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun pull(serverUrl: String, deviceId: String, deviceSecret: String, since: Long): ContactSyncResult {
        val base = syncUrl(serverUrl) ?: return ContactSyncResult.BadRequest("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("since", since.coerceAtLeast(0L).toString())
            .build()
        val request = Request.Builder().url(url).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()
        return execute(request)
    }

    suspend fun push(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        baseCursor: Long,
        changes: List<ContactDto>,
    ): ContactSyncResult {
        val base = syncUrl(serverUrl) ?: return ContactSyncResult.BadRequest("Server URL is not valid")
        val body = json.encodeToString(ContactSyncPushRequestDto(baseCursor = baseCursor, changes = changes))
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()
        return execute(request)
    }

    suspend fun dedupe(serverUrl: String, deviceId: String, deviceSecret: String): ContactDedupeResult {
        val base = dedupeUrl(serverUrl) ?: return ContactDedupeResult.BadRequest("Server URL is not valid")
        val request = Request.Builder().url(base).post("".toRequestBody(JSON_MEDIA_TYPE))
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()
        return when (
            val mapped = executeMapped(
                request = request,
                deserializer = ContactDedupeReportDto.serializer(),
                malformedMessage = "Malformed contact dedupe response",
                unauthorizedMessage = "Bad secret or unknown device",
                serviceUnavailableMessage = "Contact dedupe is not configured on the backend",
                failureMessagePrefix = "Contact dedupe failed",
            )
        ) {
            is HttpMappedResult.Success -> ContactDedupeResult.Success(mapped.value)
            is HttpMappedResult.BadRequest -> ContactDedupeResult.BadRequest(mapped.message)
            is HttpMappedResult.Unauthorized -> ContactDedupeResult.Unauthorized(mapped.message)
            is HttpMappedResult.ServiceUnavailable -> ContactDedupeResult.ServiceUnavailable(mapped.message)
            is HttpMappedResult.Retryable -> ContactDedupeResult.Retryable(mapped.message)
        }
    }

    private fun syncUrl(serverUrl: String) = pairingEndpoint(serverUrl, "/api/contacts/sync")

    private fun dedupeUrl(serverUrl: String) = pairingEndpoint(serverUrl, "/api/contacts/dedupe")

    private suspend fun execute(request: Request): ContactSyncResult {
        return when (
            val mapped = executeMapped(
                request = request,
                deserializer = ContactSyncPullResponseDto.serializer(),
                malformedMessage = "Malformed contact sync response",
                unauthorizedMessage = "Bad secret or unknown device",
                serviceUnavailableMessage = "Contact sync is not configured on the backend",
                failureMessagePrefix = "Contact sync failed",
            )
        ) {
            is HttpMappedResult.Success -> ContactSyncResult.Success(mapped.value)
            is HttpMappedResult.BadRequest -> ContactSyncResult.BadRequest(mapped.message)
            is HttpMappedResult.Unauthorized -> ContactSyncResult.Unauthorized(mapped.message)
            is HttpMappedResult.ServiceUnavailable -> ContactSyncResult.ServiceUnavailable(mapped.message)
            is HttpMappedResult.Retryable -> ContactSyncResult.Retryable(mapped.message)
        }
    }

    /** Streams the 200 body: a full contact-book pull is the second largest JSON this app reads,
     *  and `.string()` held a UTF-16 copy of it alive beside the decoded DTOs. */
    private suspend fun <T> executeMapped(
        request: Request,
        deserializer: kotlinx.serialization.DeserializationStrategy<T>,
        malformedMessage: String,
        unauthorizedMessage: String,
        serviceUnavailableMessage: String,
        failureMessagePrefix: String,
    ): HttpMappedResult<T> {
        val result = withContext(Dispatchers.IO) {
            callFactory.executeDecoding(request, json, deserializer)
        }
        val response = result.getOrNull()
            ?: return HttpMappedResult.Retryable(
                result.exceptionOrNull()?.message ?: "$failureMessagePrefix: network error",
            )

        return when (response.code) {
            200 -> response.decoded?.let { HttpMappedResult.Success(it) }
                ?: HttpMappedResult.Retryable(malformedMessage)
            400, 413 -> HttpMappedResult.BadRequest(response.errorBody.ifBlank { "Malformed request" })
            401 -> HttpMappedResult.Unauthorized(unauthorizedMessage)
            503 -> HttpMappedResult.ServiceUnavailable(serviceUnavailableMessage)
            else -> HttpMappedResult.Retryable("$failureMessagePrefix (${response.code})")
        }
    }
}
