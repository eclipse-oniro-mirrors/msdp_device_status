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
#include <ctime>
#include <dlfcn.h>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_mgr_proxy.h"
#include "devicestatus_define.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
const char *LIB_ON_SCREEN_ALGO_PATH = "/system/lib64/libon_screen.z.so";
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
const char *DEVICE_TYPE_PARA_NAME = "const.product.devicetype";
const char *PROACTIVE_SCREEN_SHOT_CAP = "screenshotIntent";
const std::vector<std::string> SUPPORT_DEVICE_TYPE = { "phone", "tablet" };
constexpr int32_t RET_NO_SUPPORT = 801;
constexpr int32_t RET_NO_PERMISSION = 201;
constexpr int32_t RET_NO_SYSTEM_CALLING = 202;
constexpr int32_t RET_NOT_REGISTER = 203;
constexpr int32_t RET_PARAM_ERR = 401;
const std::map<std::string, std::string> hapWhiteListMap = {
    {"com.huawei.hmos.vassistant", "1189827130565864320"},
};
}

OnScreenAlgorithmHandle::~OnScreenAlgorithmHandle()
{
    Clear();
}

void OnScreenAlgorithmHandle::Clear()
{
    handle = nullptr;
    pAlgorithm = nullptr;
    create = nullptr;
    destroy = nullptr;
}

OnScreenServer::~OnScreenServer()
{
    UnloadAlgoLib();
}

int32_t OnScreenServer::GetPageContent(const CallingContext &context, const ContentOption &option,
    PageContent &pageContent)
{
    std::lock_guard lockGrd(mtx_);
    int32_t ret = RET_OK;
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    if (!CheckPermission(context, PERMISSION_GET_PAGE_CONTENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_GET_PAGE_CONTENT);
        return RET_NO_PERMISSION;
    }
    if (!IsSystemCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreenContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("get page content invoke algo lib");
    ret = handle_.pAlgorithm->GetPageContent(onScreenContext, option, pageContent);
    if (ret != RET_OK) {
        FI_HILOGE("failed to get page content, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::SendControlEvent(const CallingContext &context, const ControlEvent &event)
{
    std::lock_guard lockGrd(mtx_);
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    int32_t ret = RET_OK;
    if (!CheckPermission(context, PERMISSION_SEND_CONTROL_EVENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_SEND_CONTROL_EVENT);
        return RET_NO_PERMISSION;
    }
    if (!IsSystemCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreenContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("send control event invoke algo lib");
    ret = handle_.pAlgorithm->SendControlEvent(onScreenContext, event);
    if (ret != RET_OK) {
        FI_HILOGE("failed to send control event, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::ListenLiveBroadcast()
{
    FI_HILOGI("check live start");
    std::lock_guard lockGrd(mtx_);
    int32_t ret = RET_OK;
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    ret = handle_.pAlgorithm->ListenLiveBroadcast();
    if (ret != RET_OK) {
        FI_HILOGE("failed to check live, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    std::lock_guard lockGrd(mtx_);
    int32_t ret = RET_OK;
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    FI_HILOGI("dump invoke algo lib");
    ret = handle_.pAlgorithm->Dump(fd, args);
    if (ret != RET_OK) {
        FI_HILOGE("failed to dump, err=%{public}d", ret);
    }
    NotifyClient();
    return ret;
}

int32_t OnScreenServer::RegisterScreenEventCallback(const CallingContext& context,
    int32_t windowId, const std::string& event, const sptr<IRemoteOnScreenCallback>& callback)
{
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreeContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("RegisterScreenEventCallback algo lib");
    auto ret = handle_.pAlgorithm->RegisterScreenEventCallback(onScreeContext, windowId, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("failed to RegisterScreenEventCallback, err = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::UnregisterScreenEventCallback(const CallingContext& context,
    int32_t windowId, const std::string& event, const sptr<IRemoteOnScreenCallback>& callback)
{
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreeContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("UnregisterScreenEventCallback algo lib");
    auto ret = handle_.pAlgorithm->UnregisterScreenEventCallback(onScreeContext, windowId, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("failed to UnregisterScreenEventCallback, err = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::IsParallelFeatureEnabled(const CallingContext& context,
    int32_t windowId, int32_t& outStatus)
{
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreeContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    auto ret = handle_.pAlgorithm->IsParallelFeatureEnabled(onScreeContext, windowId, outStatus);
    if (ret != RET_OK) {
        FI_HILOGE("failed to check screen change access, err=%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenServer::GetLiveStatus()
{
    FI_HILOGI("get live status");
    std::lock_guard lockGrd(mtx_);
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    return handle_.pAlgorithm->GetLiveStatus();
}

int32_t OnScreenServer::ConnectAlgoLib()
{
    return handle_.pAlgorithm == nullptr ? LoadAlgoLib() : RET_OK;
}

int32_t OnScreenServer::LoadAlgoLib()
{
    char libRealPath[PATH_MAX] = { 0 };
    if (realpath(LIB_ON_SCREEN_ALGO_PATH, libRealPath) == nullptr) {
        FI_HILOGE("get absolute path failed, ret = %{public}d", errno);
        return RET_ERR;
    }
    handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    if (handle_.handle == nullptr) {
        FI_HILOGE("dlopen failed, err:%{public}sn", dlerror());
        return RET_ERR;
    }
    handle_.create = reinterpret_cast<IOnScreenAlgorithm*(*)()>(dlsym(handle_.handle, "Create"));
    handle_.destroy = reinterpret_cast<void(*)(const IOnScreenAlgorithm*)>(dlsym(handle_.handle, "Destroy"));
    if (handle_.create == nullptr || handle_.destroy == nullptr) {
        FI_HILOGE("create is null or destoy is null");
        return RET_ERR;
    }
    if (handle_.pAlgorithm == nullptr) {
        FI_HILOGI("get on screen algo object");
        handle_.pAlgorithm = handle_.create();
        if (handle_.pAlgorithm == nullptr) {
            FI_HILOGE("create on screen algo object failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t OnScreenServer::UnloadAlgoLib()
{
    FI_HILOGE("unload exit");
    if (handle_.pAlgorithm != nullptr && handle_.destroy != nullptr) {
        handle_.destroy(handle_.pAlgorithm);
        handle_.pAlgorithm = nullptr;
    }
    handle_.Clear();
    return RET_OK;
}

bool OnScreenServer::CheckPermission(const CallingContext &context, const std::string &permission)
{
    auto type = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    FI_HILOGD("called tokenType is %{public}d", type);
    if (type == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        FI_HILOGD("called tokenType is shell, verify succ");
    }
    return Security::AccessToken::AccessTokenKit::VerifyAccessToken(context.tokenId, permission) == RET_OK;
}

bool OnScreenServer::IsSystemCalling(const CallingContext &context)
{
    if (IsSystemServiceCalling(context)) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}

bool OnScreenServer::GetAppIdentifier(const std::string& bundleName, int32_t userId, std::string& appIdentifier)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKCF(systemAbilityManager != nullptr, "get saMgr failed");
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHKCF(remoteObject != nullptr, "get remote failed");
    sptr<AppExecFwk::IBundleMgr> bundleManager = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    CHKCF(bundleManager != nullptr, "get bundleMgr failed");
    AppExecFwk::BundleInfo bundleInfo;
    int ret = bundleManager->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, userId);
    CHKCF(ret == RET_OK, "get bundle info failed");
    CHKCF(!bundleInfo.signatureInfo.appIdentifier.empty(), "appIdentifier empty");
    appIdentifier = bundleInfo.signatureInfo.appIdentifier;
    return true;
}

bool OnScreenServer::IsWhitelistAppCalling(const CallingContext &context)
{
    std::string packageName = "";
    int32_t tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if (tokenType != Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        return false;
    }
    Security::AccessToken::HapTokenInfo hapInfo;
    if (Security::AccessToken::AccessTokenKit::GetHapTokenInfo(context.tokenId, hapInfo) != RET_OK) {
        FI_HILOGE("Get hap token info fail");
        return false;
    }
    auto it = hapWhiteListMap.find(hapInfo.bundleName);
    CHKCF(it != hapWhiteListMap.end(), "bundleName not in whitelist");
    std::string appIdentifier = "";
    CHKCF(GetAppIdentifier(hapInfo.bundleName, hapInfo.userID, appIdentifier), "get appIdentifier failed");
    CHKCF(it->second == appIdentifier, "appIdentifier not match");
    return true;
}

bool OnScreenServer::IsSystemServiceCalling(const CallingContext &context)
{
    auto flag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if ((flag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) ||
        (flag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL)) {
        FI_HILOGI("system service calling, flag:%{public}u", flag);
        return true;
    }
    return false;
}

bool OnScreenServer::CheckDeviceType()
{
    std::string deviceType = OHOS::system::GetParameter(DEVICE_TYPE_PARA_NAME, "");
    return std::find(SUPPORT_DEVICE_TYPE.begin(), SUPPORT_DEVICE_TYPE.end(), deviceType) != SUPPORT_DEVICE_TYPE.end();
}

void OnScreenServer::FillDumpCommonData(OnscreenAwarenessInfo& info)
{
    info.resultCode = 0;
    info.timestamp = 605491200000;
    info.bundleName = std::string("com.ohos.duoxi");
    info.appID = std::string("wx1d2b3c4d5e6f7g8h9i10j11k12l13");
    info.appIndex = 0;
    info.pageId = std::string("1646132-45646-56465461-654654");
    info.sampleId = std::string("156481-987648-654561-454898");
    info.collectStrategy = 0;
    info.displayId = 125;
    info.windowId = 0;
}
void OnScreenServer::FillUiTreeData(std::map<std::string, ValueObj> &entityInfo)
{
    entityInfo["uiTree"] = R"({{
        "version":1.0,
        "windowid":1,
        "link":[
            {"hyperlink":"one http link"},
            {"deeplink":"one deep link"}
        ],
        "title":"hi bro."
        "componments":[
            {
                "id":123,
                "type":image,
                "bbox":[x1, y1, x2, y2, x3, y3, x4, y4]
            },
            {
                "id":456,
                "type":image,
                "bbox":[x1, y1, x2, y2, x3, y3, x4, y4]
            },
        ]
    }})";
}
void FillDumpUiTree(std::map<std::string, ValueObj> &entityInfo)
{
    OnScreenServer::FillUiTreeData(entityInfo);
}
void FillDumpContentUiTreeWithTree(std::map<std::string, ValueObj> &entityInfo)
{
    OnScreenServer::FillUiTreeData(entityInfo);
    std::vector<std::string> imagesCompID = {"165461615648", "489791849434956"};
    entityInfo["imagesCompID"] = imagesCompID;
}
void FillDumpOcr(std::map<std::string, ValueObj> &entityInfo)
{
    OnScreenServer::FillUiTreeData(entityInfo);
}
void FillDumpScreenshot(std::map<std::string, ValueObj> &entityInfo)
{
    entityInfo["screenshotID"] = R"("156-5654848-541846-454545748")";
}
void FillDumpContentLink(std::map<std::string, ValueObj> &entityInfo)
{
    AwarenessInfoPageLink link{
        .httpLink = std::string("one http link"),
        .deepLink = std::string("one deep link")
    };
    entityInfo["pagLink"] = link;
}
void FillDumpInteractionClickl(std::map<std::string, ValueObj> &entityInfo)
{
    OnScreenServer::FillUiTreeData(entityInfo);
}
void FillDumpInteractionScroll(std::map<std::string, ValueObj> &entityInfo)
{
    OnScreenServer::FillUiTreeData(entityInfo);
}
void FillDumpInteractionTextSelection(std::map<std::string, ValueObj> &entityInfo)
{
    entityInfo["textSelection"] = std::string("when you listen to the radio,lalalala,lalalala, apei");
}

void FillDumpScenarioReading(std::map<std::string, ValueObj> &entityInfo)
{
    entityInfo["title"] = std::string("yesterday once more");
    std::vector<std::string> compID = {"1", "22", "563"};
    entityInfo["content"] = compID;
    entityInfo["wordCount"] = 125;
    entityInfo["lazyLoad"] = false;
}
void FillDumpScenarioShortVideo(std::map<std::string, ValueObj> &entityInfo)
{
    entityInfo["category"] = 1;
    entityInfo["hasBackGroundMusic"] = true;
    entityInfo["imagID"] = R"("156-5654848-541846-454545748")";
    entityInfo["publisher"] = std::string("who is daddy");
    entityInfo["description"] = std::string("story about two bears and one man, hha");
    entityInfo["series"] = std::string("Bears");
    entityInfo["hotSearch"] = std::string("cartoon");
    entityInfo["SearchTips"] = std::string("protect forest");
    std::vector<std::string> position = {"1", "22", "563", "563"};
    entityInfo["position"] = position;
}
void FillDumpScenarioActivity(std::map<std::string, ValueObj> &entityInfo)
{
    OnScreenServer::FillUiTreeData(entityInfo);
}
void FillDumpScenarioTodo(std::map<std::string, ValueObj> &entityInfo)
{
    entityInfo["homeworkAssign"] = true;
    entityInfo["homeworkName"] =  std::string("find two bears");
    entityInfo["chatgroupName"] = R"("bear boy 1 group")";
    entityInfo["pageName"] = std::string("web//children's playground.");
    entityInfo["subject"] = std::string("math");
    entityInfo["assigntime"] = std::string("2025-12-03 15:56:60");
    entityInfo["deadline"] = std::string("2033-12-03 15:56:60");
    entityInfo["description"] = std::string("when can i finish my job.");
    entityInfo["teacherName"] = std::string("Ms. PIPI");
}

using FillDumpDataFunc = std::function<void(std::map<std::string, ValueObj> &)>;
std::map<std::string, FillDumpDataFunc> fillDataMap = {
    {"contentUiTree", FillDumpUiTree},
    {"contentUiOcr", FillDumpOcr},
    {"contentScreenshot", FillDumpScreenshot},
    {"contentLink", FillDumpContentLink},
    {"contentUiTreeWithImage", FillDumpContentUiTreeWithTree},
    {"interactionTextSelection", FillDumpInteractionTextSelection},
    {"interactionClick", FillDumpInteractionClickl},
    {"interactionScroll", FillDumpInteractionScroll},
    {"scenarioReading", FillDumpScenarioReading},
    {"scenarioShortVideo", FillDumpScenarioShortVideo},
    {"scenarioActivity", FillDumpScenarioActivity},
    {"scenarioTodo", FillDumpScenarioTodo},
};

OnscreenAwarenessInfo OnScreenServer::FillDumpData(const AwarenessCap& cap, const AwarenessOptions& option)
{
    OnscreenAwarenessInfo wholeInfo;
    wholeInfo.entityInfo.clear();

    FillDumpCommonData(wholeInfo);
    if (cap.capList.empty()) {
        FI_HILOGE("capList is null.");
        return wholeInfo;
    }
    for (const auto& key : cap.capList) {
        auto it = fillDataMap.find(key);
        if (it == fillDataMap.end()) {
            continue;
        }
        FI_HILOGI("cap is %s.", key.c_str());
        OnscreenEntityInfo info;
        info.entityName = key;
        it->second(info.entityInfo);
        wholeInfo.entityInfo.emplace_back(info);
    }
    return wholeInfo;
}

void OnScreenServer::NotifyClient()
{
    for (auto const &[k, v] : callbackInfo_) {
        std::vector<std::string> caps(v.begin(), v.end());
        AwarenessCap cap = {
            .capList = caps,
            .description = "",
        };
        AwarenessOptions option;
        k->OnScreenAwareness(FillDumpData(cap, option));
    }
}

bool OnScreenServer::SaveCallbackInfo(const sptr<IRemoteOnScreenCallback>& callback, const AwarenessCap& cap)
{
    auto it = callbackInfo_.find(callback);
    if (it != callbackInfo_.end()) {
        for (auto c : cap.capList) {
            it->second.insert(c);
        }
        return true;
    }
    std::set<std::string> capSet;
    for (auto c : cap.capList) {
        capSet.insert(c);
    }
    callbackInfo_[callback] = capSet;
    return true;
}

int32_t OnScreenServer::RemoveCallbackInfo(const sptr<IRemoteOnScreenCallback>& callback, const AwarenessCap& cap)
{
    auto it = callbackInfo_.find(callback);
    if (it == callbackInfo_.end()) {
        return RET_NOT_REGISTER;
    }
    for (auto c : cap.capList) {
        it->second.erase(c);
    }
    if (it->second.empty()) {
        callbackInfo_.erase(it);
    }
    return RET_OK;
}

std::vector<std::string> OnScreenServer::GetUnusedCap(const AwarenessCap& cap)
{
    std::set<std::string> usingCap;
    for (const auto& pair : callbackInfo_) {
        usingCap.insert(pair.second.begin(), pair.second.end());
    }
    std::vector<std::string> unusedCap;
    for (const auto& c : cap.capList) {
        if (usingCap.find(c) == usingCap.end()) {
            unusedCap.push_back(c);
        }
    }
    return unusedCap;
}

int32_t OnScreenServer::RegisterAwarenessCallback(const CallingContext &context, const AwarenessCap& cap,
    const sptr<IRemoteOnScreenCallback>& callback, const AwarenessOptions& option)
{
    CALL_INFO_TRACE;
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    if (!CheckPermission(context, PERMISSION_GET_PAGE_CONTENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_GET_PAGE_CONTENT);
        return RET_NO_PERMISSION;
    }
    if (!IsWhitelistAppCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    return RET_OK;
}

int32_t OnScreenServer::UnregisterAwarenessCallback(const CallingContext &context, const AwarenessCap& cap,
    const sptr<IRemoteOnScreenCallback>& callback)
{
    CALL_INFO_TRACE;
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    if (!CheckPermission(context, PERMISSION_GET_PAGE_CONTENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_GET_PAGE_CONTENT);
        return RET_NO_PERMISSION;
    }
    if (!IsWhitelistAppCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    RemoveCallbackInfo(callback, cap);
    AwarenessCap unusedCap = {
        .capList = GetUnusedCap(cap),
        .description = cap.description,
    };
    return RET_OK;
}

int32_t OnScreenServer::Trigger(const CallingContext &context, const AwarenessCap& cap, const AwarenessOptions& option,
    OnscreenAwarenessInfo& info)
{
    CALL_INFO_TRACE;
    if (!CheckDeviceType()) {
        FI_HILOGE("device type is not support");
        return RET_NO_SUPPORT;
    }
    if (!CheckPermission(context, PERMISSION_GET_PAGE_CONTENT)) {
        FI_HILOGE("checkpermission failed, premission = %{public}s", PERMISSION_GET_PAGE_CONTENT);
        return RET_NO_PERMISSION;
    }
    // proactive screenshot reuse interface
    bool hasScreenshotIntent = std::find(cap.capList.begin(), cap.capList.end(), PROACTIVE_SCREEN_SHOT_CAP) !=
        cap.capList.end();
    std::optional<std::vector<ScreenShotIntent>> intentVec = std::nullopt;
    int32_t ret = RET_OK;
    OnscreenAwarenessInfo screenshotIntentInfo;
    int32_t screenshotIntentRet = hasScreenshotIntent ?
        OnScreenShotIntent(context, option, screenshotIntentInfo) : RET_OK;
    if (!IsWhitelistAppCalling(context)) {
        FI_HILOGE("calling is not system calling");
        return RET_NO_SYSTEM_CALLING;
    }
    info = FillDumpData(cap, option);
    if (ret == RET_OK) {
        info.entityInfo.insert(info.entityInfo.end(), screenshotIntentInfo.entityInfo.begin(),
            screenshotIntentInfo.end());
    }
    return RET_OK;
}

int32_t OnScreenServer::OnScreenShotIntent(const CallingContext &context, const AwarenessOptions& option,
    OnscreenAwarenessInfo& info)
{
    // parse param
    auto windowIdVar = option.entityInfo["windowId"];
    auto screenshotVar = option.entityInfo["screenshot"];
    int32_t windowId = 0;
    std::shared_ptr<Media::PixelMap> screenshot = nullptr;
    if (!(std::holds_alternative<int32_t>(windowId) &&
        std::holds_alternative<std::shared_ptr<Media::PixelMap>>(screenshotVar))) {
        FI_HILOGE("onscreenshot windowId or screenshot type unmatch");
        return RET_PARAM_ERR;
    }
    windowId = std::get<int32_t>(windowIdVar);
    screenshot = std::get<std::shared_ptr<Media::PixelMap>>(screenshotVar);
    // invoke alg
    std::vector<ScreenShotIntent> intentVec;
    if (ConnectAlgoLib() != RET_OK) {
        FI_HILOGE("failed to load algo lib");
        return RET_NO_SUPPORT;
    }
    OnScreenCallingContext onScreenContext {
        .fullTokenId = context.fullTokenId,
        .tokenId = context.tokenId,
        .uid = context.uid,
        .pid = context.pid,
    };
    FI_HILOGI("on screenshot intent invoke algo lib");
    ret = handle_.pAlgorithm->OnScreenShotIntent(onScreenContext, windowId, screenshot, intentVec);
    if (ret != RET_OK) {
        FI_HILOGE("failed to get on screenshot intent, err=%{public}d", ret);
    }
    // convert data to info
    info.resultCode = ret;
    info.timestamp = static_cast<int64_t>(std::time(nullptr));
    for (const auto &i : intentVec) {
        std::map<std::string, std::string> intentData;
        intentData["name"] = i.name;
        intentData["param"] = i.param;
        OnscreenEntityInfo info = {
            .entityName = "screenshotIntent",
            .entityInfo = intentData
        };
        info.entityInfo.push_back(info);
    }
    return RET_OK;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS