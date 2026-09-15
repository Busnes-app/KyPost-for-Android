package org.kysecurity.mail.pgp

import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.atomic.AtomicInteger

/** The real AndroidKeyStore, except that the first [lies] `containsAlias` reads answer false.
 *  This is the transient fault the vault's absence guard exists for. */
internal fun lyingKeyStore(lies: Int): KeyStore {
    val real = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val remaining = AtomicInteger(lies)
    val spi = object : KeyStoreSpi() {
        override fun engineGetKey(alias: String, password: CharArray?): Key? = real.getKey(alias, password)
        override fun engineGetCertificateChain(alias: String): Array<Certificate>? = real.getCertificateChain(alias)
        override fun engineGetCertificate(alias: String): Certificate? = real.getCertificate(alias)
        override fun engineGetCreationDate(alias: String): Date? = real.getCreationDate(alias)
        override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<Certificate>?) =
            real.setKeyEntry(alias, key, password, chain)
        override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<Certificate>?) =
            real.setKeyEntry(alias, key, chain)
        override fun engineSetCertificateEntry(alias: String, cert: Certificate) = real.setCertificateEntry(alias, cert)
        override fun engineDeleteEntry(alias: String) = real.deleteEntry(alias)
        override fun engineAliases(): Enumeration<String> = real.aliases()
        override fun engineContainsAlias(alias: String): Boolean =
            if (remaining.getAndDecrement() > 0) false else real.containsAlias(alias)
        override fun engineSize(): Int = real.size()
        override fun engineIsKeyEntry(alias: String): Boolean = real.isKeyEntry(alias)
        override fun engineIsCertificateEntry(alias: String): Boolean = real.isCertificateEntry(alias)
        override fun engineGetCertificateAlias(cert: Certificate): String? = real.getCertificateAlias(cert)
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
    }
    return object : KeyStore(spi, real.provider, real.type) {}.apply { load(null) }
}
