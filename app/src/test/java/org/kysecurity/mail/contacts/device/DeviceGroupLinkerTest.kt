package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.data.GroupEntity
import org.kysecurity.mail.data.GroupLinkEntity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceGroupLinkerTest {
    @Test
    fun findExistingGroupRowId_noGroups_returnsNull() {
        assertNull(findExistingGroupRowId(emptyList(), "Work"))
    }

    @Test
    fun findExistingGroupRowId_matchingTitle_returnsItsRowId() {
        val existing = listOf(1L to "Family", 2L to "Work")
        assertEquals(2L, findExistingGroupRowId(existing, "Work"))
    }

    @Test
    fun findExistingGroupRowId_noMatchingTitle_returnsNull() {
        val existing = listOf(1L to "Family", 2L to "Work")
        assertNull(findExistingGroupRowId(existing, "Friends"))
    }

    @Test
    fun findExistingGroupRowId_isCaseSensitive() {
        val existing = listOf(1L to "work")
        assertNull(findExistingGroupRowId(existing, "Work"))
    }

    @Test
    fun findExistingGroupRowId_firstMatchWins() {
        val existing = listOf(1L to "Work", 2L to "Work")
        assertEquals(1L, findExistingGroupRowId(existing, "Work"))
    }

    @Test
    fun groupRenameTargets_noLinks_returnsEmpty() {
        val groups = listOf(GroupEntity(id = "g1", name = "Work", rev = 2))
        assertTrue(groupRenameTargets(emptyList(), groups).isEmpty())
    }

    @Test
    fun groupRenameTargets_linkedGroupRenamedOnBackend_returnsAndroidRowIdWithFreshName() {
        val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 42L))
        val groups = listOf(GroupEntity(id = "g1", name = "Work Squad", rev = 3))
        assertEquals(listOf(42L to "Work Squad"), groupRenameTargets(links, groups))
    }

    @Test
    fun groupRenameTargets_linkedGroupNameUnchanged_stillReturnsPair() {
        // The current name is always resolved; whether it differs is decided by renameIfNeeded.
        val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 42L))
        val groups = listOf(GroupEntity(id = "g1", name = "Work", rev = 1))
        assertEquals(listOf(42L to "Work"), groupRenameTargets(links, groups))
    }

    @Test
    fun groupRenameTargets_linkToDeletedBackendGroup_isSkipped() {
        // The group was removed from the backend (and thus from GroupSyncRepository's refreshed
        // GroupEntity cache) but the link row is still present -- nothing to rename to.
        val links = listOf(GroupLinkEntity(groupId = "gone", androidGroupRowId = 99L))
        assertTrue(groupRenameTargets(links, emptyList()).isEmpty())
    }

    @Test
    fun groupRenameTargets_multipleLinks_resolvesEachIndependently() {
        val links = listOf(
            GroupLinkEntity(groupId = "g1", androidGroupRowId = 1L),
            GroupLinkEntity(groupId = "g2", androidGroupRowId = 2L),
            GroupLinkEntity(groupId = "gone", androidGroupRowId = 3L),
        )
        val groups = listOf(
            GroupEntity(id = "g1", name = "Family", rev = 1),
            GroupEntity(id = "g2", name = "Work Squad", rev = 5),
        )
        assertEquals(
            listOf(1L to "Family", 2L to "Work Squad"),
            groupRenameTargets(links, groups),
        )
    }

    @Test
    fun groupRemovals_areExactlyTheLinksWhoseBackendGroupIsGone() {
        val gone = GroupLinkEntity(groupId = "gone", androidGroupRowId = 3L)
        val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 1L), gone)

        assertEquals(listOf(gone to true), groupRemovals(links, listOf(GroupEntity(id = "g1", name = "Family", rev = 1))))
    }

    /** Two backend groups matched by title share row 7: removing one must not delete it. */
    @Test
    fun groupRemovals_keepARowALiveGroupStillLinksTo() {
        val gone = GroupLinkEntity(groupId = "g2", androidGroupRowId = 7L)
        val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 7L), gone)

        assertEquals(listOf(gone to false), groupRemovals(links, listOf(GroupEntity(id = "g1", name = "Team", rev = 1))))
    }

    /** Moved from "Customers" (row 1) to "Former customers" (row 2) on the web: the phone gains row
     *  2 and loses row 1, and its membership in another account's group (row 9) is left alone. */
    @Test
    fun membershipChanges_addsMissing_deletesExtra_ignoresOtherAccountsGroups() {
        val (add, delete) = membershipChanges(current = listOf(1L, 9L), wanted = listOf(2L), owned = setOf(1L, 2L, 3L))

        assertEquals(setOf(2L), add)
        assertEquals(setOf(1L), delete)
    }

    @Test
    fun membershipChanges_inStep_changesNothing_andNeverAddsAGroupWeDoNotOwn() {
        assertEquals(emptySet<Long>() to emptySet(), membershipChanges(listOf(1L, 1L), listOf(1L), setOf(1L)))
        assertEquals(emptySet<Long>() to emptySet(), membershipChanges(emptyList(), listOf(9L), setOf(1L)))
    }
}
