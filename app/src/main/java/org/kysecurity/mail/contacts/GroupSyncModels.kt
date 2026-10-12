package org.kysecurity.mail.contacts

import kotlinx.serialization.Serializable

/** Matches the backend's `groups.Group` JSON shape (`{id, name, rev, createdAt, updatedAt}`)
 *  exactly, mirroring [ContactDto]'s convention of 1:1 field names. */
@Serializable
data class GroupDto(
    val id: String = "",
    val name: String = "",
    val rev: Long = 0,
    val createdAt: String? = null,
    val updatedAt: String? = null,
)

/** `GET /api/groups` responds `{"groups": [...]}`, not a bare array. `groups` is required: a
 *  reply without it must fail the refresh, not read as "no groups" and delete them all. */
@Serializable
data class GroupsListResponseDto(
    val groups: List<GroupDto>,
)
