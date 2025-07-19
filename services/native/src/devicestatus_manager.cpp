/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "devicestatus_manager.h"

#include "image_packer.h"
#include "iservice_registry.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "wm_common.h"

#include "accessibility_manager.h"
#include "devicestatus_define.h"
#include "devicestatus_napi_manager.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
    const std::string BUNDLE_NAME = "com.tencent.wechat";
    const int32_t SYSTEM_BAR_HIDDEN = 0;
    const int32_t PAGE_SCROLL_ENVENT = 1;
}
std::shared_ptr<DeviceStatusManager> DeviceStatusManager::g_deviceManager_;
std::mutex DeviceStatusManager::g_mutex_;

void DeviceStatusManager::DeviceStatusCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    CHKPV(remote);
    FI_HILOGI("Recv death notice");
}

void DeviceStatusManager::BoomerangCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    CHKPV(remote);
    FI_HILOGI("Recv death notice");
    if (manager_ == nullptr) {
        return;
    }
    std::lock_guard lock(manager_->mutex_);
    for (auto& entry : manager_->boomerangListeners_) {
        auto& callbacks = entry.second;
        auto it = callbacks.begin();
        if (it == callbacks.end()) {
            FI_HILOGI("this app is not Subscribe");
        }
        while (it != callbacks.end()) {
            auto callback_remote = (*it)->AsObject();
            if (callback_remote && callback_remote == remote) {
                it = callbacks.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (manager_->notityListener_ != nullptr && remote == manager_->notityListener_->AsObject()) {
        FI_HILOGI("the screenshot app has died");
        manager_->notityListener_ = nullptr;
    }
}

void DeviceStatusManager::AccessibilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    std::lock_guard<std::mutex> guard(g_mutex_);
    switch (systemAbilityId) {
        case WINDOW_MANAGER_SERVICE_ID: {
            g_deviceManager_ = std::make_shared<DeviceStatusManager>();
            sptr<IWindowSystemBarPropertyChangedListener> systemBarListener =
                sptr<SystemBarStyleChangedListener>::MakeSptr();
            CHKPV(systemBarListener);
            Rosen::WMError ret =
                WindowManager::GetInstance().RegisterWindowSystemBarPropertyChangedListener(systemBarListener);
            if (ret != Rosen::WMError::WM_OK) {
                FI_HILOGI("Register Window SystemBarStyle Change faild");
            }
            break;
        }
        default: {
            FI_HILOGW("Service ID that does not need to be processed");
            break;
        }
    }
}

void DeviceStatusManager::AccessibilityStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    std::lock_guard<std::mutex> guard(g_mutex_);
    CHKPV(g_deviceManager_);
    if (systemAbilityId == WINDOW_MANAGER_SERVICE_ID) {
        CHKPV(g_deviceManager_);
        g_deviceManager_->lastEnable_ = true;
    }
}

void DeviceStatusManager::SystemBarStyleChangedListener::OnWindowSystemBarPropertyChanged(WindowType type,
    const SystemBarProperty& systemBarProperty)
{
    std::lock_guard<std::mutex> guard(g_mutex_);
    FI_HILOGI("OnWindowSystemBarPropertyChanged status:%{public}d", systemBarProperty.enable_);
    CHKPV(g_deviceManager_);
    if (type == WindowType::WINDOW_TYPE_STATUS_BAR && systemBarProperty.enable_ != g_deviceManager_->lastEnable_) {
        g_deviceManager_->lastEnable_ = systemBarProperty.enable_;
    }
    if (g_deviceManager_->lastEnable_) {
        if (g_deviceManager_->isAccessibilityInit_) {
            ACCESSIBILITY_MANAGER.AccessibilityDisconnect();
        }
    } else {
        g_deviceManager_->HandlerPageScrollerEvent(SYSTEM_BAR_HIDDEN);
    }
}

bool DeviceStatusManager::Init()
{
    CALL_DEBUG_ENTER;
    if (devicestatusCBDeathRecipient_ == nullptr) {
        devicestatusCBDeathRecipient_ = new (std::nothrow) DeviceStatusCallbackDeathRecipient();
        if (devicestatusCBDeathRecipient_ == nullptr) {
            FI_HILOGE("devicestatusCBDeathRecipient_ failed");
            return false;
        }
    }

    if (boomerangCBDeathRecipient_ == nullptr) {
        boomerangCBDeathRecipient_ = new (std::nothrow) BoomerangCallbackDeathRecipient(this);
        if (boomerangCBDeathRecipient_ == nullptr) {
            FI_HILOGE("boomerangCBDeathRecipient_ failed");
            return false;
        }
    }

    msdpImpl_ = std::make_shared<DeviceStatusMsdpClientImpl>();
    CHKPF(msdpImpl_);

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPF(samgrProxy);

    auto windowStatusChange = sptr<AccessibilityStatusChange>::MakeSptr();
    int32_t ret = samgrProxy->SubscribeSystemAbility(WINDOW_MANAGER_SERVICE_ID, windowStatusChange);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeSystemAbility service faild on window manager");
        return false;
    }
    FI_HILOGD("Init success");
    return true;
}

Data DeviceStatusManager::GetLatestDeviceStatusData(Type type)
{
    CALL_DEBUG_ENTER;
    Data data = {type, OnChangedValue::VALUE_EXIT};
    if ((type <= TYPE_INVALID) || (type >= TYPE_MAX)) {
        FI_HILOGE("GetLatestDeviceStatusData type_:%{public}d is error", type);
        return data;
    }
    if (msdpImpl_ == nullptr) {
        FI_HILOGE("msdpImpl_ is nullptr");
        data.value = OnChangedValue::VALUE_INVALID;
        return data;
    }
    msdpData_ = msdpImpl_->GetObserverData();
    for (auto iter = msdpData_.begin(); iter != msdpData_.end(); ++iter) {
        if (data.type == iter->first) {
            data.value = iter->second;
            return data;
        }
    }
    return {type, OnChangedValue::VALUE_INVALID};
}

bool DeviceStatusManager::Enable(Type type)
{
    CALL_DEBUG_ENTER;
    if ((type <= TYPE_INVALID) || (type >= TYPE_MAX)) {
        FI_HILOGE("Check type is invalid");
        return false;
    }
    InitAlgoMngrInterface(type);
    InitDataCallback();
    return true;
}

bool DeviceStatusManager::Disable(Type type)
{
    CALL_DEBUG_ENTER;
    CHKPF(msdpImpl_);

    if (msdpImpl_->Disable(type) != RET_OK) {
        FI_HILOGE("Disable msdp impl failed");
        return false;
    }

    return true;
}

bool DeviceStatusManager::InitAlgoMngrInterface(Type type)
{
    CALL_DEBUG_ENTER;
    CHKPF(msdpImpl_);

    if (msdpImpl_->InitMsdpImpl(type) != RET_OK) {
        FI_HILOGE("Init msdp impl failed");
        return false;
    };
    return true;
}

int32_t DeviceStatusManager::InitDataCallback()
{
    CALL_DEBUG_ENTER;
    CHKPF(msdpImpl_);
    DeviceStatusMsdpClientImpl::CallbackManager callback = [this](const Data &data) {
        return this->MsdpDataCallback(data);
    };
    if (msdpImpl_->RegisterImpl(callback) == RET_ERR) {
        FI_HILOGE("Register impl failed");
    }
    return true;
}

int32_t DeviceStatusManager::MsdpDataCallback(const Data &data)
{
    NotifyDeviceStatusChange(data);
    return RET_OK;
}

int32_t DeviceStatusManager::NotifyDeviceStatusChange(const Data &devicestatusData)
{
    CALL_DEBUG_ENTER;
    FI_HILOGI("type:%{public}d, value:%{public}d", devicestatusData.type, devicestatusData.value);
    std::set<const sptr<IRemoteDevStaCallback>, classcomp> listeners;
    std::lock_guard lock(mutex_);
    auto iter = listeners_.find(devicestatusData.type);
    if (iter == listeners_.end()) {
        FI_HILOGE("type:%{public}d is not exits", devicestatusData.type);
        return false;
    }
    if ((devicestatusData.type <= TYPE_INVALID) || (devicestatusData.type >= TYPE_MAX)) {
        FI_HILOGE("Check devicestatusData.type is invalid");
        return false;
    }
    listeners = (std::set<const sptr<IRemoteDevStaCallback>, classcomp>)(iter->second);
    for (const auto &listener : listeners) {
        if (listener == nullptr) {
            FI_HILOGE("listener is nullptr");
            return false;
        }
        FI_HILOGI("type:%{public}d, arrs_:%{public}d", devicestatusData.type, arrs_[devicestatusData.type]);
        switch (arrs_[devicestatusData.type]) {
            case ENTER: {
                if (devicestatusData.value == VALUE_ENTER) {
                    listener->OnDeviceStatusChanged(devicestatusData);
                }
                break;
            }
            case EXIT: {
                if (devicestatusData.value == VALUE_EXIT) {
                    listener->OnDeviceStatusChanged(devicestatusData);
                }
                break;
            }
            case ENTER_EXIT: {
                listener->OnDeviceStatusChanged(devicestatusData);
                break;
            }
            default: {
                FI_HILOGE("OnChangedValue is unknown");
                break;
            }
        }
    }
    return RET_OK;
}

void DeviceStatusManager::Subscribe(Type type, ActivityEvent event, ReportLatencyNs latency,
    sptr<IRemoteDevStaCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPV(callback);
    if ((type <= TYPE_INVALID) || (type >= TYPE_MAX)) {
        FI_HILOGE("Subscribe type_:%{public}d is error", type_);
        return;
    }
    if ((event < ENTER) || (event > ENTER_EXIT)) {
        FI_HILOGE("Subscribe event_:%{public}d is error", event_);
        return;
    }
    event_ = event;
    type_ = type;
    std::lock_guard lock(mutex_);
    arrs_ [type_] = event_;
    FI_HILOGI("type_:%{public}d, event:%{public}d", type_, event);
    std::set<const sptr<IRemoteDevStaCallback>, classcomp> listeners;
    auto object = callback->AsObject();
    CHKPV(object);
    FI_HILOGI("listeners_.size:%{public}zu", listeners_.size());
    auto dtTypeIter = listeners_.find(type);
    if (dtTypeIter == listeners_.end()) {
        if (listeners.insert(callback).second) {
            FI_HILOGI("No found set list of type, insert success");
            object->AddDeathRecipient(devicestatusCBDeathRecipient_);
        }
        auto [_, ret] = listeners_.insert(std::make_pair(type, listeners));
        if (!ret) {
            FI_HILOGW("type is duplicated");
        }
    } else {
        FI_HILOGI("callbacklist.size:%{public}zu", listeners_[dtTypeIter->first].size());
        auto iter = listeners_[dtTypeIter->first].find(callback);
        if (iter != listeners_[dtTypeIter->first].end()) {
            return;
        }
        if (listeners_[dtTypeIter->first].insert(callback).second) {
            FI_HILOGI("Find set list of type, insert success");
            object->AddDeathRecipient(devicestatusCBDeathRecipient_);
        }
    }
    if (!Enable(type)) {
        FI_HILOGE("Enable failed");
        return;
    }
}

void DeviceStatusManager::Unsubscribe(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPV(callback);
    if ((type <= TYPE_INVALID) || (type >= TYPE_MAX)) {
        FI_HILOGE("Unsubscribe type_:%{public}d is error", type);
        return;
    }
    if ((event < ENTER) || (event > ENTER_EXIT)) {
        FI_HILOGE("Unsubscribe event_:%{public}d is error", event);
        return;
    }
    auto object = callback->AsObject();
    CHKPV(object);
    std::lock_guard lock(mutex_);
    FI_HILOGI("listeners_.size:%{public}zu, type:%{public}d event:%{public}d", listeners_.size(),
        static_cast<int32_t>(type), event);
    auto dtTypeIter = listeners_.find(type);
    if (dtTypeIter == listeners_.end()) {
        FI_HILOGE("Failed to find listener for type");
        return;
    }
    FI_HILOGI("callbacklist.size:%{public}zu", listeners_[dtTypeIter->first].size());
    auto iter = listeners_[dtTypeIter->first].find(callback);
    if (iter != listeners_[dtTypeIter->first].end()) {
        if (listeners_[dtTypeIter->first].erase(callback) != 0) {
            object->RemoveDeathRecipient(devicestatusCBDeathRecipient_);
            if (listeners_[dtTypeIter->first].empty()) {
                listeners_.erase(dtTypeIter);
            }
        }
    }
    FI_HILOGI("listeners_.size:%{public}zu", listeners_.size());
    if (listeners_.empty()) {
        Disable(type);
    } else {
        FI_HILOGI("Other subscribe exist");
    }
}

int32_t DeviceStatusManager::Subscribe(int32_t type, const std::string &bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    if ((type <= BOOMERANG_TYPE_INVALID) || (type >= BOOMERANG_TYPE_MAX)) {
        FI_HILOGE("Subscribe boomerangType_:%{public}d is error", boomerangType_);
        return RET_ERR;
    }
    boomerangType_ = type;
    std::lock_guard lock(mutex_);
    std::set<const sptr<IRemoteBoomerangCallback>, boomerangClasscomp> listeners;
    auto object = callback->AsObject();
    CHKPR(object, RET_ERR);
    FI_HILOGI("boomerangListeners_.size:%{public}zu", boomerangListeners_.size());
    auto dtTypeIter = boomerangListeners_.find(bundleName);
    if (dtTypeIter == boomerangListeners_.end()) {
        if (listeners.insert(callback).second) {
            FI_HILOGI("No found set list of type, insert success");
            object->AddDeathRecipient(boomerangCBDeathRecipient_);
        }
        auto [_, ret] = boomerangListeners_.insert(std::make_pair(bundleName, listeners));
        if (!ret) {
            FI_HILOGW("type is duplicated");
        }
    } else {
        FI_HILOGI("callbacklist.size:%{public}zu", boomerangListeners_[dtTypeIter->first].size());
        auto iter = boomerangListeners_[dtTypeIter->first].find(callback);
        if (iter != boomerangListeners_[dtTypeIter->first].end()) {
            FI_HILOGI("Subscription information of this type already exists");
        }
        if (boomerangListeners_[dtTypeIter->first].insert(callback).second) {
            FI_HILOGI("Find set list of type, insert success");
            object->AddDeathRecipient(boomerangCBDeathRecipient_);
        }
    }
    return RET_OK;
}
 
int32_t DeviceStatusManager::Unsubscribe(int32_t type, const std::string &bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    if ((type <= BOOMERANG_TYPE_INVALID) || (type >= BOOMERANG_TYPE_MAX)) {
        FI_HILOGE("Unsubscribe type_:%{public}d is error", type);
        return RET_ERR;
    }
    auto object = callback->AsObject();
    CHKPR(object, RET_ERR);
    std::lock_guard lock(mutex_);
    auto dtTypeIter = boomerangListeners_.find(bundleName);
    if (dtTypeIter == boomerangListeners_.end()) {
        FI_HILOGE("Failed to find listener for type");
        return RET_ERR;
    }
    FI_HILOGI("callbacklist.size:%{public}zu", boomerangListeners_[dtTypeIter->first].size());
    auto iter = boomerangListeners_[dtTypeIter->first].find(callback);
    if (iter != boomerangListeners_[dtTypeIter->first].end()) {
        if (boomerangListeners_[dtTypeIter->first].erase(callback) != 0) {
            object->RemoveDeathRecipient(boomerangCBDeathRecipient_);
            if (boomerangListeners_[dtTypeIter->first].empty()) {
                boomerangListeners_.erase(dtTypeIter);
            }
        }
    }
    FI_HILOGI("listeners_.size:%{public}zu", boomerangListeners_.size());
    return RET_OK;
}
 
int32_t DeviceStatusManager::NotifyMetadata(const std::string &bundleName, sptr<IRemoteBoomerangCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    auto object = callback->AsObject();
    CHKPR(object, RET_ERR);
    std::lock_guard lock(mutex_);
    auto iter = boomerangListeners_.find(bundleName);
    if (iter == boomerangListeners_.end()) {
        FI_HILOGE("bundleName:%{public}s is not exits", bundleName.c_str());
        return RET_ERR;
    }
    auto& callbacks = iter->second;
    if (callbacks.size() == 0) {
        FI_HILOGE("this hap is not Subscribe envent");
        return RET_ERR;
    }

    for (const auto &listener : callbacks) {
        if (listener == nullptr) {
            CHKPR(listener, RET_ERR);
        }
        BoomerangData data {};
        data.type = BoomerangType::BOOMERANG_TYPE_BOOMERANG;
        data.status = BoomerangStatus::BOOMERANG_STATUS_SCREEN_SHOT;
        listener->OnScreenshotResult(data);
    }
    object->AddDeathRecipient(boomerangCBDeathRecipient_);
    notityListener_ = callback;
    auto callbackIter = bundleNameCache_.find(callback);
    if (callbackIter == bundleNameCache_.end()) {
        bundleNameCache_.emplace(callback, bundleName);
    }
    return RET_OK;
}

int32_t DeviceStatusManager::GetBundleNameByCallback(std::string &bundleName)
{
    auto iter = bundleNameCache_.find(notityListener_);
    if (iter != bundleNameCache_.end()) {
        bundleName = iter->second;
        bundleNameCache_.erase(iter);
        return RET_OK;
    }
    return RET_ERR;
}

int32_t DeviceStatusManager::GetBundleNameByApplink(std::string &bundleName, const std::string &metadata)
{
    if (bundleManager_ == nullptr) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        CHKPR(systemAbilityManager, E_DEVICESTATUS_GET_SYSTEM_ABILITY_MANAGER_FAILED);
        sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        CHKPR(remoteObject, E_DEVICESTATUS_GET_SERVICE_FAILED);
        bundleManager_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        CHKPR(bundleManager_, RET_ERR);
    }
    OHOS::AAFwk::Want want;
    want.SetUri(metadata);
    std::vector<int32_t> ids;
    ErrCode accountRet = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (accountRet != ERR_OK || ids.empty()) {
        FI_HILOGE("Get userId from active Os AccountIds fail, ret : %{public}d", accountRet);
        return RET_ERR;
    }
    int32_t userId = ids[0];
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APP_LINKING);
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    bundleManager_->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    if (abilityInfos.empty()) {
        FI_HILOGE("Get abilityInfos fail.");
        return RET_ERR;
    }
    bundleName = abilityInfos[0].bundleName;
    return RET_OK;
}

int32_t DeviceStatusManager::SubmitMetadata(const std::string &metadata)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPR(notityListener_, RET_ERR);
    std::string callbackBundleName;
    std::string applinkBundleName;
    auto callbackRet = GetBundleNameByCallback(callbackBundleName);
    if (callbackRet != RET_OK) {
        FI_HILOGE("Get callbackBundleName fail.");
        return callbackRet;
    }
    auto applinkRet = GetBundleNameByApplink(applinkBundleName, metadata);
    if (applinkRet != RET_OK) {
        FI_HILOGE("Get applinkBundleName fail.");
        return applinkRet;
    }
    if (callbackBundleName.compare(applinkBundleName) != 0) {
        FI_HILOGE("BundleName Check fail.");
        std::string emptyMetadata;
        notityListener_->OnNotifyMetadata(emptyMetadata);
    } else {
        notityListener_->OnNotifyMetadata(metadata);
    }
    return RET_OK;
}
 
int32_t DeviceStatusManager::BoomerangEncodeImage(std::shared_ptr<Media::PixelMap> pixelMap,
    const std::string &metadata, sptr<IRemoteBoomerangCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, RET_ERR);
    CHKPR(callback, RET_ERR);
    std::lock_guard lock(mutex_);
    std::shared_ptr<Media::PixelMap> encodePixelMap;
    auto algo = std::make_shared<BoomerangAlgoImpl>();
    CHKPR(algo, RET_ERR);
    algo->EncodeImage(pixelMap, metadata, encodePixelMap);
    CHKPR(encodePixelMap, RET_ERR);
    callback->OnEncodeImageResult(encodePixelMap);
    return RET_OK;
}

int32_t DeviceStatusManager::BoomerangDecodeImage(std::shared_ptr<Media::PixelMap> pixelMap,
    sptr<IRemoteBoomerangCallback> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, RET_ERR);
    CHKPR(callback, RET_ERR);
    std::lock_guard lock(mutex_);
    std::string metadata;
    auto algo = std::make_shared<BoomerangAlgoImpl>();
    CHKPR(algo, RET_ERR);
    algo->DecodeImage(pixelMap, metadata);
    callback->OnNotifyMetadata(metadata);
    return RET_OK;
}

int32_t DeviceStatusManager::LoadAlgorithm()
{
    CALL_DEBUG_ENTER;
    if (msdpImpl_ != nullptr) {
        msdpImpl_->LoadAlgoLibrary();
    }
    return RET_OK;
}

int32_t DeviceStatusManager::UnloadAlgorithm()
{
    CALL_DEBUG_ENTER;
    if (msdpImpl_ != nullptr) {
        msdpImpl_->UnloadAlgoLibrary();
    }
    return RET_OK;
}

int32_t DeviceStatusManager::GetPackageName(AccessTokenID tokenId, std::string &packageName)
{
    int32_t tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    switch (tokenType) {
        case ATokenTypeEnum::TOKEN_HAP: {
            HapTokenInfo hapInfo;
            if (AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo) != 0) {
                FI_HILOGE("Get hap token info failed");
                return RET_ERR;
            }
            packageName = hapInfo.bundleName;
            break;
        }
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL: {
            NativeTokenInfo tokenInfo;
            if (AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) != 0) {
                FI_HILOGE("Get native token info failed");
                return RET_ERR;
            }
            packageName = tokenInfo.processName;
            break;
        }
        default: {
            FI_HILOGE("token type not match");
            break;
        }
    }
    return RET_OK;
}

int32_t DeviceStatusManager::GetFocuseWindowId(int32_t &windowId, std::string &bundleName)
{
    std::vector<sptr<Rosen::WindowVisibilityInfo>> winInfos;
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().GetVisibilityWindowInfo(winInfos);
    if (ret != Rosen::WMError::WM_OK) {
        FI_HILOGI("get windowInfos failed, ret=%{public}d", ret);
        return RET_ERR;
    }
    for (const auto &winInfo : winInfos) {
        if (winInfo == nullptr) {
            continue;
        }
        if (winInfo->IsFocused()) {
            windowId = static_cast<int32_t>(winInfo->GetWindowId());
            bundleName =  winInfo->GetBundleName();
            FI_HILOGD("get focuse windowId, ret=%{public}d, bundleName:%{public}s",
                winInfo->GetWindowId(), winInfo->GetBundleName().c_str());
            return RET_OK;
        }
    }
    return RET_ERR;
}

void DeviceStatusManager::SystemBarHiddedInit()
{
    ACCESSIBILITY_MANAGER.AccessibilityConnect([this](int32_t value) {
        std::lock_guard<std::mutex> guard(g_mutex_);
        CHKPV(g_deviceManager_);
        switch (value) {
            case AccessibilityStatus::ON_ABILITY_CONNECTED: {
                g_deviceManager_->isAccessibilityInit_ = true;
                FI_HILOGI("Accessibility service has connect");
                break;
            }
            case AccessibilityStatus::ON_ABILITY_SCROLLED_EVENT: {
                g_deviceManager_->HandlerPageScrollerEvent(PAGE_SCROLL_ENVENT);
                break;
            }
            case AccessibilityStatus::ON_ABILITY_DISCONNECTED: {
                g_deviceManager_->isAccessibilityInit_ = false;
                FI_HILOGI("Accessibility service has disConnect");
                break;
            }
            default: {
                FI_HILOGW("Accessibility Unknown Event");
                break;
            }
        }
    });
}

void DeviceStatusManager::HandlerPageScrollerEvent(int32_t event)
{
    int32_t windowId;
    std::string bundleName;
    int32_t result = GetFocuseWindowId(windowId, bundleName);
    if (result != RET_OK) {
        FI_HILOGE("get the focuse widowId faild, result=%{public}d", result);
        return;
    }
    CHKPV(g_deviceManager_);
    if (g_deviceManager_->lastEnable_ || bundleName != BUNDLE_NAME) {
        FI_HILOGD("The current status bar is in display mode or does not belong to the whitelist application");
        return;
    }

    if (event == SYSTEM_BAR_HIDDEN) {
        SystemBarHiddedInit();
    }

    std::shared_ptr<Media::PixelMap> screenShot;
    Rosen::WMError ret = WindowManager::GetInstance().GetSnapshotByWindowId(windowId, screenShot);
    if (ret == Rosen::WMError::WM_OK) {
        OnSurfaceCapture(windowId, screenShot);
    }
}

void DeviceStatusManager::OnSurfaceCapture(int32_t windowId, std::shared_ptr<Media::PixelMap> &screenShot)
{
    auto algo = std::make_shared<BoomerangAlgoImpl>();
    CHKPV(algo);
    std::string metadata;
    algo->DecodeImage(screenShot, metadata);
    std::lock_guard lock(countMutex_);
    if (!metadata.empty()) {
        FI_HILOGI("Boomerang Algo decode image result:%{public}s", metadata.c_str());
        retryCount = 0;
        return;
    }
    if (retryCount < 1) {
        retryCount++;
        Rosen::WMError ret = WindowManager::GetInstance().GetSnapshotByWindowId(windowId, screenShot);
        if (ret == Rosen::WMError::WM_OK) {
            OnSurfaceCapture(windowId, screenShot);
        }
        retryCount = 0;
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
