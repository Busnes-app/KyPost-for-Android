# R8 rules for the release build: only what R8 cannot infer, reflection and manifest-named classes.

# kotlinx.serialization
# Serializers are generated as nested classes and looked up reflectively; without these the
# relay DTOs deserialize to nothing and every network response reads as "malformed".
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class **$$serializer { *** descriptor; }
-if @kotlinx.serialization.Serializable class org.kysecurity.mail.**
-keepclassmembers class <1> {
    static <1>$Companion Companion;
    public static **$* *;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class org.kysecurity.mail.**$$serializer { *; }

# Tink's shaded protobuf parse failure
# EncryptedPrefs.isProtobufParseFailure identifies this by simpleName, because it is the one proof
# that an encrypted store's keyset is destroyed rather than the Keystore being briefly unwell.
# Renamed, that comparison never matches: release refused to reopen a store debug would have
# repaired, and the swallowed failure surfaced as "this device is not enrolled". Names only — the
# class may still be shrunk if nothing uses it. checkRuntimeMatchedClassNames enforces this.
-keepnames class com.google.crypto.tink.shaded.protobuf.InvalidProtocolBufferException

# jakarta.mail content handlers
# META-INF/mailcap names these as strings and MailcapCommandMap loads them by name, so no bytecode
# refers to them and R8 removed all five. jakarta.activation then falls back to
# DataSourceDataContentHandler, whose getContent() returns an InputStream instead of a String or a
# MimeMultipart, and PgpMimeReader reads that as "no body at all" — which is every decrypted
# message failing to render in release while debug was fine. Members too, not just the names: they
# are reached through DataContentHandler and shrinking them leaves the class an empty shell.
#
# Listed one by one rather than `handlers.**`: the wildcard also keeps image_gif and image_jpeg,
# which reference java.awt.Image and java.awt.Toolkit and fail the build on Android. mailcap does
# not declare those, and AWT does not exist here. These five are exactly what it declares, and
# checkRuntimeMatchedClassNames holds the same five.
-keep class org.eclipse.angus.mail.handlers.text_plain { *; }
-keep class org.eclipse.angus.mail.handlers.text_html { *; }
-keep class org.eclipse.angus.mail.handlers.text_xml { *; }
-keep class org.eclipse.angus.mail.handlers.multipart_mixed { *; }
-keep class org.eclipse.angus.mail.handlers.message_rfc822 { *; }

# Manifest-declared components
# Instantiated by name by the framework; only the class name and no-arg constructor must survive.
-keep class org.kysecurity.mail.KyPostApp { <init>(); }
-keep class org.kysecurity.mail.security.EphemeralAttachmentProvider { <init>(); }
-keep class org.kysecurity.mail.push.KyPostFirebaseMessagingService { <init>(); }
-keep class org.kysecurity.mail.push.KyPostUnifiedPushService { <init>(); }
-keep class org.kysecurity.mail.contacts.device.KyPostContactAuthenticatorService { <init>(); }

# Referenced only by name from AndroidManifest metadata, so R8 cannot see the reference and would
# strip it — leaving splits silently dead in release while they work in debug.
-keep class org.kysecurity.mail.ui.SplitInitializer { <init>(); }

# WorkManager instantiates workers reflectively via their (Context, WorkerParameters) constructor.
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# Diagnostics
# Keep line numbers so a release crash report is readable, but rename the source file so the
# original paths are not embedded in the APK.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# X509TrustManagerExtensions finds this by reflection; OkHttp's Android chain cleaner, and so the
# leaf pin, run through it. Renamed, OkHttp silently falls back to its basic cleaner.
-keepclassmembers class org.kysecurity.mail.security.StrongTls$StrongTrustManager {
    public java.util.List checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String, java.lang.String);
}
