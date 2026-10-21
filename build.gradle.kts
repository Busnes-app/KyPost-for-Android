// Floors for build-tool transitives with published advisories that AGP 9.4.1, the newest
// stable, still requests. Constraints only raise a version; a later AGP asking for more wins.
// Drop each line once AGP's own request reaches it. app/build.gradle.kts does the same for lint.
buildscript {
    dependencies {
        constraints {
            classpath("org.bouncycastle:bcprov-jdk18on:1.86")
            classpath("org.bouncycastle:bcpkix-jdk18on:1.86")
            classpath("org.bouncycastle:bcutil-jdk18on:1.86")
            classpath("org.apache.commons:commons-lang3:3.21.0")
            classpath("org.bitbucket.b_c:jose4j:0.9.7")
            classpath("org.jdom:jdom2:2.0.6.1")
            // AGP asks for KGP 2.2.10; without this Gradle fetches that version's metadata
            // before the catalog's KGP wins.
            classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:${libs.versions.kotlin.get()}")
        }
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.google.services) apply false
    alias(libs.plugins.ksp) apply false
}
