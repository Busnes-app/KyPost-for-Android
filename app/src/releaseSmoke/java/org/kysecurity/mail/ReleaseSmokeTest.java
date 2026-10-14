package org.kysecurity.mail;

import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry;
import androidx.test.runner.lifecycle.Stage;

import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Runs against the minified release build (see kypostReleaseSmoke in app/build.gradle.kts), where a
 * missing keep rule fails at launch rather than at build time. Java and string names on purpose:
 * R8 renames or drops app classes and Kotlin stdlib members a test would otherwise link against,
 * while manifest components and resource names survive.
 */
@RunWith(AndroidJUnit4.class)
public class ReleaseSmokeTest {
    private static final String PAIRING = "org.kysecurity.mail.push.PushPairingActivity";
    private static final String UNLOCK = "org.kysecurity.mail.security.UnlockActivity";
    private static final long TIMEOUT_MS = 20_000;

    private final Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
    private final Context context = instrumentation.getTargetContext();

    @Test
    public void launcherOpensPairingOnAFreshInstall() {
        Intent launch = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
        start(launch);
        assertResumedWithView(PAIRING, "btnScanQr");
    }

    @Test
    public void pairingLinkOpensPairing() {
        start(new Intent(Intent.ACTION_VIEW,
                Uri.parse("kypost://native-pair?sub=smoke&srv=https%3A%2F%2Fpair.example&pt=smoke"))
                .setPackage(context.getPackageName()));
        assertResumedWithView(PAIRING, "btnScanQr");
    }

    @Test
    public void unlockScreenInflates() {
        start(new Intent().setClassName(context, UNLOCK));
        assertResumedWithView(UNLOCK, "unlockPinField");
    }

    private void start(Intent intent) {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
    }

    /** Polls, because the startup wipe check can recreate the first instance before it settles. */
    private void assertResumedWithView(String activityClass, String viewId) {
        boolean[] found = {false};
        long deadline = SystemClock.uptimeMillis() + TIMEOUT_MS;
        while (!found[0] && SystemClock.uptimeMillis() < deadline) {
            instrumentation.runOnMainSync(() -> {
                for (Activity activity : ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)) {
                    if (!activity.getClass().getName().equals(activityClass)) continue;
                    int id = activity.getResources().getIdentifier(viewId, "id", activity.getPackageName());
                    found[0] = id != 0 && activity.findViewById(id) != null;
                }
            });
            if (!found[0]) SystemClock.sleep(250);
        }
        assertTrue(activityClass + " never resumed showing " + viewId, found[0]);
    }
}
