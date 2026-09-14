package org.kysecurity.mail

import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SourceRulesTest {

    @Test
    fun noDataClassCarriesKeyMaterialWithoutOverridingEquality() {
        val offenders = mainSources().flatMap { file ->
            dataClassesIn(file.readText())
                .filter { PARAM_IS_KEY_MATERIAL.containsMatchIn(it.parameters) }
                .filterNot { it.declaresOwnEquality() }
                .map { "${file.path}: data class ${it.name}" }
        }
        assertEquals(
            emptyList(), offenders,
            "Use a plain class (or override equals/hashCode). See WrappedSecret and PinHash.",
        )
    }

    @Test
    fun noDataClassPrintsASecretOrAPlaintextBody() {
        val offenders = mainSources().flatMap { file ->
            dataClassesIn(file.readText())
                .filter { clazz -> clazz.parameterNames().any { it in SENSITIVE_PROPERTY_NAMES } }
                .filterNot { it.declaresOwnToString() }
                .map { clazz ->
                    val named = clazz.parameterNames().filter { it in SENSITIVE_PROPERTY_NAMES }
                    "${file.path}: data class ${clazz.name} (${named.joinToString()})"
                }
        }
        assertEquals(
            emptyList(), offenders,
            "Override toString() to redact. See PgpMimeReader.DecryptedBody.",
        )
    }

    /** Every transport that receives a push must decide what it is the same way.
     *
     *  The Firebase and UnifiedPush services each used to make that call themselves and drifted:
     *  only one of them checked for an MFA challenge, so a challenge delivered over UnifiedPush
     *  was read as mail, failed to parse, and was dropped in silence. IncomingPushRouter is the
     *  single answer now, and a service reaching past it to a parser directly is the exact shape
     *  of the regression. */
    @Test
    fun pushReceivingServicesRouteThroughIncomingPushRouter() {
        val offenders = mainSources()
            .filter { it.relativePath.substringAfterLast('/') in PUSH_RECEIVING_SERVICES }
            .filter { file ->
                val text = file.readText()
                PARSER_CALLED_DIRECTLY.containsMatchIn(text)
            }
            .map { it.path }
        assertEquals(
            emptyList(), offenders,
            "Call IncomingPushRouter.route(data) and branch on IncomingPush instead. " +
                "See IncomingPushRouter for why this is one decision and not one per transport.",
        )
    }

    @Test
    fun jvmTestedCodeDoesNotUseTheStubbedAndroidApisThatFailSilently() {
        val testPaths = sourcesUnder(TEST_ROOT).map { it.relativePath }.toSet()
        val offenders = mainSources().filter { it.relativePath.removeSuffix(".kt") + "Test.kt" in testPaths }
            .flatMap { file ->
                IMPORT.findAll(file.readText()).map { it.groupValues[1] }
                    .filter { imported -> SILENTLY_STUBBED.any { imported == it || imported.startsWith("$it.") } }
                    .map { "${file.path}: import $it" }
                    .toList()
            }
        assertEquals(
            emptyList(), offenders,
            "These return defaults rather than throwing under isReturnDefaultValues.",
        )
    }

    @Test
    fun broadCatchesInSuspendingFilesAddressCancellation() {
        val offenders = mainSources().filter { file ->
            val text = file.readText()
            "suspend fun" in text &&
                BROAD_CATCH.containsMatchIn(text) &&
                "CancellationException" !in text
        }.map { it.path }
        assertEquals(
            emptyList(), offenders,
            "catch (e: Exception) swallows CancellationException. Rethrow it, or say why this file need not.",
        )
    }

    /** A statement wedged onto the same line as the brace that opens its function. Sixteen of these
     *  existed across every Activity in the app — the residue of a mechanical refactor nobody read
     *  afterwards. There is no formatter on the build (adding one means regenerating the pinned
     *  dependency-verification metadata, which CI deliberately refuses), so this is the check. */
    @Test
    fun noStatementHidesOnAFunctionsOpeningBraceLine() {
        val offenders = mainSources().flatMap { file ->
            file.readText().lineSequence().withIndex()
                .filter { (_, line) -> STATEMENT_ON_BRACE_LINE.containsMatchIn(line) }
                .map { (index, line) -> "${file.path}:${index + 1}: ${line.trim().take(80)}" }
                .toList()
        }
        assertEquals(
            emptyList(), offenders,
            "Put the statement on its own line. A refactor left 16 of these and no formatter caught it.",
        )
    }

    /** Every write in the security package uses `commit()`, and every one of them says why. The
     *  exception that mattered was the ledger row that makes an out-of-sandbox attachment
     *  wipeable: it used `apply()`, in a file whose own comment stated the rule. */
    @Test
    fun securityPackageWritesArePersistedSynchronously() {
        val offenders = mainSources()
            .filter { "/security/" in it.relativePath || it.relativePath.startsWith("security/") }
            .flatMap { file ->
                file.readText().lineSequence().withIndex()
                    .filter { (_, line) -> ASYNC_PREFS_WRITE.containsMatchIn(line) }
                    .map { (index, line) -> "${file.path}:${index + 1}: ${line.trim().take(80)}" }
                    .toList()
            }
        assertEquals(
            emptyList(), offenders,
            "Use commit(): an async flush that has not landed when the process dies loses the write.",
        )
    }

    /** `deriveKeys` throws when the Keystore pepper cannot be read, and every PIN path has to abort
     *  on that rather than die: a Keystore fault is not a wrong PIN. `changePin` was the one caller
     *  that skipped it, so an unreadable Keystore killed the process in the middle of the staged
     *  write the PIN change exists to survive. */
    @Test
    fun credentialDerivationsHandleAnUnavailableKeystore() {
        val offenders = mainSources()
            .filterNot { it.relativePath.substringAfterLast('/') in RAW_DERIVE_KEYS_OWNERS }
            .flatMap { file ->
                file.readText().lineSequence().withIndex()
                    .filter { (_, line) -> RAW_DERIVE_KEYS.containsMatchIn(line) }
                    .map { (index, line) -> "${file.path}:${index + 1}: ${line.trim().take(80)}" }
                    .toList()
            }
        assertEquals(
            emptyList(), offenders,
            "Use CredentialCipher.deriveKeysOrNull and abort on null. See PepperUnavailableException.",
        )
    }

    @Test
    fun webmailHandoffCannotTransferOrDiscardTheComposition() {
        val compose = mainSources().single { it.relativePath.endsWith("/ComposeActivity.kt") }.readText()
        val handoff = compose.substringAfter("private fun handOffToWebmail()")
            .substringBefore("override fun onStop()")
        val forbidden = listOf("exportHtml", "MailDraft(", ".saveDraft(", "ComposeDraftCache.clear", "finish()")
            .filter { it in handoff }
        assertEquals(
            emptyList(),
            forbidden,
            "Webmail handoff may open only a data-free URL and must leave the live composer intact.",
        )
    }

    private class Source(val path: String, val relativePath: String, private val file: File) {
        fun readText(): String = file.readText()
    }

    private fun mainSources(): List<Source> = sourcesUnder(MAIN_ROOT)

    private fun sourcesUnder(root: String): List<Source> {
        val dir = listOf(File(root), File("app/$root")).firstOrNull { it.isDirectory }
        // Loud, not vacuous. A silently empty tree would make both tests above pass forever, which
        // is the failure mode this whole file exists to stop.
        assertNotNull(dir, "Could not locate $root from ${File(".").absolutePath}")
        return dir.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .map { Source(it.path, it.relativeTo(dir).invariantPath(), it) }
            .toList()
    }

    private fun File.invariantPath(): String = path.replace(File.separatorChar, '/')

    private class DataClass(val name: String, val parameters: String, private val body: String) {
        fun declaresOwnEquality(): Boolean =
            body.contains("override fun equals") && body.contains("override fun hashCode")

        fun declaresOwnToString(): Boolean = body.contains("override fun toString")

        fun parameterNames(): List<String> {
            val names = mutableListOf<String>()
            var depth = 0
            var atTopLevelStart = true
            var index = 0
            while (index < parameters.length) {
                when (parameters[index]) {
                    '(', '<', '[' -> depth++
                    ')', '>', ']' -> depth--
                    ',' -> if (depth == 0) atTopLevelStart = true
                }
                if (depth == 0 && atTopLevelStart) {
                    val match = PROPERTY_DECL.find(parameters, index)
                    if (match != null && match.range.first <= index + LOOKAHEAD_CHARS) {
                        names += match.groupValues[1]
                        atTopLevelStart = false
                        index = match.range.last
                        continue
                    }
                }
                index++
            }
            return names
        }
    }

    private fun dataClassesIn(source: String): List<DataClass> =
        DATA_CLASS_HEADER.findAll(source).mapNotNull { match ->
            val open = match.range.last
            var depth = 0
            var i = open
            while (i < source.length) {
                when (source[i]) {
                    '(' -> depth++
                    ')' -> if (--depth == 0) break
                }
                i++
            }
            if (i >= source.length) return@mapNotNull null
            DataClass(
                name = match.groupValues[1],
                parameters = source.substring(open + 1, i),
                body = source.substring(i, minOf(source.length, i + BODY_SCAN_CHARS)),
            )
        }.toList()

    private companion object {
        val PUSH_RECEIVING_SERVICES = setOf(
            "KyPostFirebaseMessagingService.kt",
            "KyPostUnifiedPushService.kt",
        )

        /** Either payload parser named directly by a push-receiving service. */
        val PARSER_CALLED_DIRECTLY = Regex("""(MfaChallengePayloadParser|PushPayloadParser)\s*\.\s*parse""")

        /** May derive raw: the declaration itself, and the manager whose every entry point already
         *  catches [org.kysecurity.mail.security.PepperUnavailableException]. */
        val RAW_DERIVE_KEYS_OWNERS = setOf("CredentialCipher.kt", "AppLockManager.kt")

        /** `deriveKeysOrNull(` does not match: `OrNull` sits where the paren must be. */
        val RAW_DERIVE_KEYS = Regex("""CredentialCipher\s*\.\s*deriveKeys\s*\(""")

        const val MAIN_ROOT = "src/main/java"
        const val TEST_ROOT = "src/test/java"

        /** How far past a class header to look for equality overrides; generous on purpose. */
        const val BODY_SCAN_CHARS = 1200

        /** How far past a top-level comma a `val` may sit and still be that parameter's — covers
         *  annotations and modifiers (`@SerialName("x") val ...`, `internal val ...`). */
        const val LOOKAHEAD_CHARS = 200

        /** `) {   stmt` — a function body opening and its first statement on one line. Two or more
         *  spaces, so a legitimate one-line body and `{ it.y }` lambdas are not hits. */
        val STATEMENT_ON_BRACE_LINE = Regex("""\bfun\s+[^\n]*\)\s*(?::[^\n{]*)?\{ {2,}\S""")

        /** SharedPreferences writes that may not have landed when the process dies. */
        val ASYNC_PREFS_WRITE = Regex("""\.edit\(\)[^\n]*\.apply\(\)|^\s*\.apply\(\)\s*$""")

        val DATA_CLASS_HEADER = Regex("""\bdata class\s+(\w+)\s*\(""")
        val PROPERTY_DECL = Regex("""\bval\s+(\w+)\s*:""")

        /** Types whose generated `equals`/`hashCode` are identity-based, not structural. */
        val PARAM_IS_KEY_MATERIAL =
            Regex(""":\s*(ByteArray|CharArray|SecretKeySpec|SecretKey)\b""")

        /** Names meaning "holds a secret or plaintext"; `publicKey` is deliberately absent. */
        val SENSITIVE_PROPERTY_NAMES = setOf(
            "plaintext", "body", "html", "plain", "preview", "protectedSubject", "encryptedPayload",
            "secret", "deviceSecret", "pairingToken", "passphrase",
            "privateKey", "armoredPrivateKey",
        )
        // `pin` is absent on purpose: the only `pin` property is an SPKI hash of a public cert.
        val IMPORT = Regex("""^import\s+([\w.]+)""", RegexOption.MULTILINE)
        val SILENTLY_STUBBED = listOf("android.util.Base64", "org.json")
        val BROAD_CATCH = Regex("""catch\s*\(\s*\w+\s*:\s*(Exception|Throwable)\s*\)""")
    }
}
