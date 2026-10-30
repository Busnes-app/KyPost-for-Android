package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

class BarBottomInsetTest {

    @Test
    fun keyboardDown_padsByTheNavigationBar() {
        assertEquals(42, barBottomInset(systemBarsBottom = 42, imeBottom = 0))
    }

    @Test
    fun keyboardUp_android14ReportingBarsAsKeyboardHeight_padsNothing() {
        // Values read off a moto g play 2024 with the keyboard up on Compose.
        assertEquals(0, barBottomInset(systemBarsBottom = 588, imeBottom = 588))
    }

    @Test
    fun keyboardUp_keyboardCoversTheNavigationBar_padsNothing() {
        assertEquals(0, barBottomInset(systemBarsBottom = 42, imeBottom = 900))
    }
}
