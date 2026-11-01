package org.kysecurity.mail

/** Recreates an Activity under an open SystemUI prompt. On CI emulators this has left window focus
 *  dead for the rest of the boot, failing every later Espresso test, so CI runs these in their own
 *  pass after the main suite (`notAnnotation` / `annotation` in ci.yml). */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS)
annotation class SystemPromptLifecycle
