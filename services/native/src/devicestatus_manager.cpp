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
#include "wm_common.h"
#include "ui_content_service_interface.h"
#include "ui_content_proxy.h"

#include "accessibility_manager.h"
#include "boomerang_surfacecapture_callback.h"
#include "devicestatus_define.h"
#include "devicestatus_napi_manager.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
    constexpr int32_t IMAGE_PAIR_LIST_MAX_LENGTH = 100;
    std::mutex g_screenShotMutex_;
    const std::string BUNDLENAME = "com.tencent.wechat";
    DeviceStatusManager* g_deviceManager { nullptr };
}

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
    CHKPV(manager_);
    switch (systemAbilityId) {
        case ACCESSIBILITY_MANAGER_SERVICE_ID: {
            ACCESSIBILITY_MANAGER.AccessibilityConnect([this](int32_t value) {
                if (value == AccessibilityStatus::ON_ABILITY_CONNECTED) {
                    manager_->isAccessbilityInit = true;
                    FI_HILOGI("Accessibility service has connect");
                }
                if (value == AccessibilityStatus::ON_ABILITY_SCROLLED_EVENT) {
                    manager_->handlerPageScrollerEnvent();
                }
            });
            break;
        }
        case WINDOW_MANAGER_SERVICE_ID: {
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
    CHKPV(manager_);
    if (systemAbilityId == ACCESSIBILITY_MANAGER_SERVICE_ID) {
        FI_HILOGE("the accessibility service died");
    } else if (systemAbilityId == WINDOW_MANAGER_SERVICE_ID) {
        manager_->g_lastEnable = true;
    }
}

void DeviceStatusManager::SystemBarStyleChangedListener::OnWindowSystemBarPropertyChanged(WindowType type,
    const SystemBarProperty& systemBarProperty)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (g_deviceManager == nullptr) {
        g_deviceManager = new (std::nothrow) DeviceStatusManager();
    }
    CHKPV(g_deviceManager);
    if (type == WindowType::WINDOW_TYPE_STATUS_BAR && systemBarProperty.enable_ != g_deviceManager->g_lastEnable) {
        g_deviceManager->g_lastEnable = systemBarProperty.enable_;
    }
    if (!g_deviceManager->g_lastEnable) {
        g_deviceManager->handlerPageScrollerEnvent();
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

    accessibilityStatusChange_ = new (std::nothrow) AccessibilityStatusChange(this);
    CHKPF(accessibilityStatusChange_);
    int32_t ret = samgrProxy->SubscribeSystemAbility(ACCESSIBILITY_MANAGER_SERVICE_ID, accessibilityStatusChange_);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeSystemAbility accessibility error");
    }
    ret = samgrProxy->SubscribeSystemAbility(WINDOW_MANAGER_SERVICE_ID, accessibilityStatusChange_);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeSystemAbility window manager error");
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
    return RET_OK;
}

int32_t DeviceStatusManager::SubmitMetadata(const std::string &metadata)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPR(notityListener_, RET_ERR);
    notityListener_->OnNotifyMetadata(metadata);
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
    std::shared_ptr<BoomerangAlgoImpl> algo = std::make_shared<BoomerangAlgoImpl>();
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
            windowId = winInfo->GetWindowId();
            bundleName =  winInfo->GetBundleName();
            FI_HILOGD("get focuse windowId, ret=%{public}d, bundleName:%{public}s",
                windowId, bundleName.c_str());
            return RET_OK;
        }
    }
    return RET_ERR;
}

void showImagesCallback(std::vector<std::pair<int32_t, std::shared_ptr<Media::PixelMap>>> imagePairList)
{
    std::unique_lock<std::mutex> lock(g_screenShotMutex_);
    int32_t maxArea = 0;
    std::shared_ptr<Media::PixelMap> encodeImage;
    for (size_t index = 0; index < imagePairList.size(); index++) {
        if (index > IMAGE_PAIR_LIST_MAX_LENGTH) {
            FI_HILOGE("showImagesCallback, imagePairList images cut: %{public}d to %{public}d",
                static_cast<int32_t>(imagePairList.size()), IMAGE_PAIR_LIST_MAX_LENGTH);
            break;
        }
        std::pair<int32_t, std::shared_ptr<Media::PixelMap>> imagePair = imagePairList[index];
        if (imagePair.second == nullptr || imagePair.second->GetPixels() == nullptr) {
            FI_HILOGE("showImagesCallback, empty pixelmap");
            continue;
        }
        int32_t imageWidth = imagePair.second->GetWidth();
        int32_t imageHeight = imagePair.second->GetHeight();
        int32_t area = imageWidth * imageHeight;
        if (area > maxArea) {
            maxArea = area;
            encodeImage = imagePair.second;
        }
    }
    CHKPV(encodeImage);

    std::string metadata;
    std::shared_ptr<BoomerangAlgoImpl> algo = std::make_shared<BoomerangAlgoImpl>();
    CHKPV(algo);
    algo->DecodeImage(encodeImage, metadata);
    FI_HILOGI("jjy Boomerang Algo decode image result:%{public}s", metadata.c_str());
}

void DeviceStatusManager::handlerPageScrollerEnvent()
{
    std::lock_guard lock(mutex_);
    int32_t windowId;
    std::string bundleName;
    int32_t result = GetFocuseWindowId(windowId, bundleName);
    if (result != RET_OK) {
        FI_HILOGE("get the focuse widowId faild, result=%{public}d", result);
        return;
    }
    if (g_lastEnable || bundleName != BUNDLENAME) {
        FI_HILOGD("The current status bar is in display mode or does not belong to the whitelist application");
        return;
    }
    sptr<IRemoteObject> tmpRemoteObj = nullptr;
    auto ret = OHOS::Rosen::WindowManager::GetInstance().GetUIContentRemoteObj(windowId, tmpRemoteObj);
    if (tmpRemoteObj == nullptr || static_cast<uint32_t>(ret) != RET_OK) {
        FI_HILOGE("tempRemoteObj is null or get uicontent remote faild");
        return;
    }
    sptr<Ace::IUiContentService> service = iface_cast<Ace::IUiContentService>(tmpRemoteObj);
    CHKPV(service);
    std::string connResult;
    auto connectCallback = [&connResult](const std::string &data) -> void {
        connResult = data;
        FI_HILOGE("Connected before getCurrentImagesShowing %{public}s", connResult.c_str());
    };
    if (!service->IsConnect()) {
        service->Connect(connectCallback);
    }

    int32_t getImagesShowingRes = service->GetCurrentImagesShowing(showImagesCallback);
    if (getImagesShowingRes != RET_OK) {
        FI_HILOGI("getCurrentImagesShowing result faild: %{public}d", getImagesShowingRes);
    }
}

void DeviceStatusManager::OnSurfaceCapture(std::shared_ptr<Media::PixelMap> screenShot)
{
    auto algo = std::make_shared<BoomerangAlgoImpl>();
    CHKPV(algo);
    std::string metadata;
    algo->DecodeImage(screenShot, metadata);
    if (metadata.empty()) {
        return;
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
