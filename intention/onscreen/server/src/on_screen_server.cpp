/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "on_screen_server.h"

#include <algorithm>
#include <dlfcn.h>
// TODO rm
#include <fstream>
#include <vector>

#include "devicestatus_define.h"
#include "if_system_ability_manager.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
const char *LIB_HA_EXPAND_PATH = "libha_client_expand.z.so";
const char *GET_PAGE_INFO_FUNC = "_ZN4OHOS7HaCloud17HaClientExpandApi11GetPageInfoERKNSt3__h12"
    "basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEESA_RS8_";
const char *OPTION = "{\"pageInfoOption\":6, \"behaviorOption\":0, \"callbackOption\":0,"
    "\"recallOption\":{\"treeWhiteList\":[], \"snapshotBlackList\":[]}}";
const char *WINDOW_NAME = "focus";
}

void *g_haExpandClientHandle = nullptr;
void *g_getPageInfoFunc = nullptr;

int32_t OnScreenServer::GetPageContent(CallingContext &context, const ContentOption &option, PageContent &pageContent)
{
    Rosen::WindowInfoOption windowInfoOption;
    option.windowInfoFilterOption =
        (Rosen::WindowInfoFilterOption::VISIBLE | Rosen::WindowInfoFilterOption::EXCLUDE_SYSTEM);
    std::vector<sptr<Rosen::WindowInfo>> windowInfos;
    // ListWindowInfo
    int32_t ret = static_cast<int32_t>(Rosen::WindowManager::GetInstance().ListWindowInfo(windowInfoOption, windowInfos));
    if (ret != RET_OK) {
        FI_HILOGE("list window info failed, ret = %{public}d", ret);
        return ret;
    }
    // find window id
    auto iter = std::find_if(windowInfos.begin(), windowInfos.end(), [&option](const sptr<Rosen::WindowInfo> &windowInfo) {
        // filter floating window
        if (windowInfo.windowMetaInfo.windowMode == Rosen::WindowMode::WINDOW_MODE_FLOATING) {
            return false;
        }
        return option.windowId == windowInfo.windowMetaInfo.windowId;
    });
    if (iter == windowInfos.end()) {
        FI_HILOGE("windowid is not exist");
        return RET_OK;
    }
    // get page content
    CHK_RET_PRINT_AND_RET(ConstructPageContent(option, *iter, pageContent), "ConstructPageContent");
    return RET_OK;
}

int32_t OnScreenServer::SendControlEvent(CallingContext &context, const ControlEvent &event)
{
    return RET_OK;
}

int32_t OnScreenServer::GetPageInfo(const std::string &window, const std::string &option, std::string &pageInfo)
{
    int32_t ret = RET_OK;
    if (g_haExpandClientHandle == nullptr) {
        ret = LoadHAExpandClient();
        if (ret != RET_OK) {
            FI_HILOGE("load ha expand client failed");
            return ret;
        }
    }
    if (g_getPageInfoFunc == nullptr) {
        g_getPageInfoFunc = dlsym(g_haExpandClientHandle, GET_PAGE_INFO_FUNC);
        if (g_getPageInfoFunc == nullptr) {
            FI_HILOGE("dlsym failed, reason:%{public}sn", dlerror());
            return RET_ERR;
        }
    }
    auto getPageInfo =
        reinterpret_cast<int32_t(*)(const std::string&, const std::string&, std::string&)>(g_getPageInfoFunc);
    ret = getPageInfo(window, option, pageInfo);
    if (ret != RET_OK) {
        FI_HILOGE("failed to get page info, ret = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::LoadHAExpandClient()
{
    CALL_DEBUG_ENTER;
    g_haExpandClientHandle = dlopen(LIB_HA_EXPAND_PATH, RTLD_NOW);
    if (g_haExpandClientHandle == nullptr) {
        FI_HILOGE("dlopen ha_expand_client failed, reason:%{public}sn", dlerror());
        return RET_ERR;
    }
    return RET_OK;
}

int32_t OnScreenServer::UnloadHAExpandClient()
{
    CALL_DEBUG_ENTER;
    if (g_haExpandClientHandle == nullptr) {
        return RET_OK;
    }
    FI_HILOGI("start unload");
    int32_t ret = dlclose(g_haExpandClientHandle);
    if (ret != RET_OK) {
        FI_HILOGE("dlclose err. ret = %{public}d", ret);
        return RET_ERR;
    }
    g_haExpandClientHandle = nullptr;
    g_getPageInfoFunc = nullptr;
}

int32_t OnScreenServer::ConnectBundleMgr()
{
    if (bundleMgrProxy_ == nullptr) {
        return RET_OK;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        FI_HILOGE("failed to get system ability mgr");
        return RET_ERR;
    }
    sptr<IRemoteObject> remoteObj = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        FI_HILOGE("failed to get remoteobj of bundle mgr");
        return RET_ERR;
    }
    bundleMgrProxy_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    if (bundleMgrProxy_ == nullptr) {
        FI_HILOGE("failed to get bundle manager proxy");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t OnScreenServer::ResetBundleMgr()
{
    FI_HILOGW("bundleMgrProxy_ reset");
    bundleMgrProxy_ = nullptr;
}

int32_t OnScreenServer::ConstructPageContent(const ContentOption &option, const sptr<Rosen::WindowInfo> windowInfo,
    PageContent &pageContent)
{
    if (windowInfo == nullptr) {
        FI_HILOGE("windowInfo is nullptr");
        return RET_ERR;
    }
    // windowId
    pageContent.winId = windowInfo->windowMetaInfo.windowId;
    FI_HILOGI("winid = %{public}d", pageContent.winId);
    // AppInfo
    CHK_RET_PRINT_AND_RET(GetAppInfo(windowInfo, pageContent.appInfo), "GetAppInfo");
    // PageInfo Get
    std::string pageInfo;
    CHK_RET_PRINT_AND_RET(GetPageInfo(WINDOW_NAME, OPTION, pageInfo), "GetPageInfo");
    // ContentUnderstand
    if (option.contentUnderstand) {
        CHK_RET_PRINT_AND_RET(ContentUnderstand(pageInfo, pageContent), "ContentUnderstand");
    }
    // PageLink
    if (option.pageLink) {
        CHK_RET_PRINT_AND_RET(GetPageLink(pageInfo, pageContent), "GetPageLink");
    }
    // TextOnly
    if (option.textOnly) {
        CHK_RET_PRINT_AND_RET(GetParagraphs(pageInfo, pageContent), "GetParagraphs");
    }
    // ScreenShot
    if (option.screenshot) {
        CHK_RET_PRINT_AND_RET(static_cast<int32_t>(Rosen::WindowManager::GetInstance().
            GetSnapshotByWindowId(windowInfo->windowMetaInfo.windowId, pageContent.screenshot)), "GetSnapshot");
    }
    return RET_OK;
}

int32_t OnScreenServer::GetAppInfo(const sptr<Rosen::WindowInfo> windowInfo, AppInfo &appInfo)
{
    appInfo.bundleName = windowInfo->windowMetaInfo.bundleName;
    AppExecFwk::BundleInfo bundleInfo;
    int32_t localId = 0;
    CHK_RET_PRINT_AND_RET(AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(localId),
        "GetForegroundOsAccountLocalId");
    CHK_RET_PRINT_AND_RET(ConnectBundleMgr(), "ConnectBundleMgr");
    CHK_RET_PRINT_AND_RET(bundleMgrProxy_->GetBundleInfoV9(appInfo.bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION),
        bundleInfo, localId), "GetBundleInfoV9");
    appInfo.name = bundleInfo.applicationInfo.label;
    appInfo.iconPath = bundleInfo.applicationInfo.iconPath;
    FI_HILOGI("GetAppInfo: name=%{public}s, bundleName=%{public}s, iconPath=%{public}s",
        appInfo.name.c_str(), appInfo.bundleName.c_str(), appInfo.iconPath.c_str());
    return RET_OK;
}

int32_t OnScreenServer::ContentUnderstand(const std::string pageInfo, PageContent &pageContent)
{
    return RET_OK;
}

int32_t OnScreenServer::GetPageLink(const std::string pageInfo, PageContent &pageContent)
{
    return RET_OK;
}

int32_t OnScreenServer::GetParagraphs(const std::string pageInfo, PageContent &pageContent)
{
    return RET_OK;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS