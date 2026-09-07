package com.webreverse.mcp.browser.tabs

import com.webreverse.mcp.browser.engine.BrowserService
import com.webreverse.mcp.browser.engine.BrowserSession
import com.webreverse.mcp.core.common.event.BrowserEvent
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.model.BrowserTab
import com.webreverse.mcp.core.common.model.RecentlyClosedTab
import com.webreverse.mcp.core.common.model.TabGroup
import com.webreverse.mcp.core.common.util.Ids
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** 标签页管理器：多标签、标签组、最近关闭 */
class TabManager(
    private val browserService: BrowserService,
    private val eventBus: EventBus,
) {
    private val _tabGroups = MutableStateFlow<List<TabGroup>>(emptyList())
    val tabGroups: StateFlow<List<TabGroup>> = _tabGroups.asStateFlow()

    private val _recentlyClosed = MutableStateFlow<List<RecentlyClosedTab>>(emptyList())
    val recentlyClosed: StateFlow<List<RecentlyClosedTab>> = _recentlyClosed.asStateFlow()

    val tabs: StateFlow<List<BrowserTab>> get() = browserService.tabs
    val activeTabId: StateFlow<String?> get() = browserService.activeTabId

    suspend fun createTab(url: String = ""): BrowserSession = browserService.createTab(url)

    suspend fun getSession(tabId: String?): BrowserSession? = browserService.getSession(tabId)

    suspend fun closeTab(tabId: String) {
        val session = browserService.getSession(tabId)
        session?.let {
            _recentlyClosed.value = listOf(
                RecentlyClosedTab(id = tabId, title = it.engine.currentTitle().orEmpty(), url = it.engine.currentUrl().orEmpty())
            ) + _recentlyClosed.value
        }
        browserService.closeTab(tabId)
        eventBus.tryEmit(BrowserEvent.TabClosed(tabId))
    }

    suspend fun activateTab(tabId: String) {
        browserService.activateTab(tabId)
        eventBus.tryEmit(BrowserEvent.TabActivated(tabId))
    }

    suspend fun duplicateTab(tabId: String): BrowserSession? {
        val session = browserService.getSession(tabId) ?: return null
        val url = session.engine.currentUrl() ?: return null
        return browserService.createTab(url)
    }

    fun createGroup(name: String, tabIds: List<String> = emptyList()): TabGroup {
        val group = TabGroup(id = Ids.uuid(), name = name, tabIds = tabIds)
        _tabGroups.value = _tabGroups.value + group
        return group
    }

    fun addToGroup(groupId: String, tabId: String) {
        _tabGroups.value = _tabGroups.value.map { group ->
            if (group.id == groupId) group.copy(tabIds = group.tabIds + tabId) else group
        }
    }

    fun removeFromGroup(tabId: String) {
        _tabGroups.value = _tabGroups.value.map { group ->
            group.copy(tabIds = group.tabIds.filterNot { it == tabId })
        }
    }

    fun deleteGroup(groupId: String) {
        _tabGroups.value = _tabGroups.value.filterNot { it.id == groupId }
    }

    fun restoreRecentlyClosed(): String? {
        val closed = _recentlyClosed.value.firstOrNull() ?: return null
        _recentlyClosed.value = _recentlyClosed.value.drop(1)
        return closed.url
    }

    suspend fun closeAll() = browserService.closeAll()
}
