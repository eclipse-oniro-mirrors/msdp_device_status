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

#include "pull_throw_listener.h"

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "devicestatus_define.h"
#include "drag_manager.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "PullThrowListener"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string SETTING_URI_PROXY = "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string SETTING_VK_KEY = "virtualKeyBoardType";
constexpr int32_t DATA_SHARE_READY = 0;
constexpr int32_t DATA_SHARE_NOT_READY = 1055;
constexpr int32_t DECEM_BASE = 10;
} // namespace

PullThrowListener::PullThrowListener(DragManager* manager) : manager_(manager)
{
    FI_HILOGI("PullThrowListener initialized with DragManager");
}

PullThrowListener::~PullThrowListener() {}

bool PullThrowListener::RegisterFoldStatusListener()
{
    foldStatusListener_ = new (std::nothrow) FoldStatusListener(this);
    if (foldStatusListener_ == nullptr) {
        FI_HILOGE("Allocate FoldStatusListener failed");
        return false;
    }
    auto ret = Rosen::DisplayManager::GetInstance().RegisterFoldStatusListener(foldStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        FI_HILOGE("RegisterFoldStatusListener failed");
        delete foldStatusListener_;
        return false;
    }
    FI_HILOGI("RegisterFoldStatusListener success");
    return true;
}

void PullThrowListener::FoldStatusListener::OnFoldStatusChanged(Rosen::FoldStatus foldStatus)
{
    CHKPV(listener_);
    CHKPV(listener_->manager_);
    FI_HILOGD("OnFoldStatusChanged foldStatus is %{public}d, throw state: %{public}d",
              static_cast<int32_t>(foldStatus), listener_->manager_->throwState_);
    
    if (foldStatus != Rosen::FoldStatus::HALF_FOLD && listener_->manager_->throwState_ != ThrowState::NOT_THROW) {
        std::shared_ptr<MMI::PointerEvent> pointerEvent = listener_->manager_->currentPointerEvent_;
        CHKPV(pointerEvent);
        pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL);
        MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
        FI_HILOGI("OnFoldStatusChanged throw stop");
    }
}

bool PullThrowListener::RegisterScreenMagneticStateListener()
{
    screenMagneticStateListener_ = new (std::nothrow) ScreenMagneticStateListener(this);
    if (screenMagneticStateListener_ == nullptr) {
        FI_HILOGE("Allocate ScreenMagneticStateListener failed");
        return false;
    }
    auto ret = Rosen::DisplayManager::GetInstance().RegisterScreenMagneticStateListener(screenMagneticStateListener_);
    if (ret != Rosen::DMError::DM_OK) {
        FI_HILOGE("RegisterScreenMagneticStateListener failed");
        delete screenMagneticStateListener_;
        return false;
    }
    FI_HILOGI("RegisterScreenMagneticStateListener success");

    return true;
}

void PullThrowListener::ScreenMagneticStateListener::OnScreenMagneticStateChanged(bool isMagneticState)
{
    CHKPV(listener_);
    CHKPV(listener_->manager_);
    FI_HILOGD("ScreenMagneticListener, isMagneticState:%{public}u", isMagneticState);
    listener_->currentMagneticState_ = isMagneticState;
    if (isMagneticState != false && listener_->manager_->throwState_ != ThrowState::NOT_THROW) {
        std::shared_ptr<MMI::PointerEvent> pointerEvent = listener_->manager_->currentPointerEvent_;
        CHKPV(pointerEvent);
        pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_PULL_CANCEL);
        MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
        FI_HILOGI("OnScreenMagneticStateChanged throw stop");
    }
}

std::shared_ptr<DataShare::DataShareHelper> PullThrowListener::CreateDataShareHelper()
{
    if (remoteObj_ == nullptr) {
        FI_HILOGD("remoteObj_ is nullptr");
        return nullptr;
    }
    auto [ret, helper] = DataShare::DataShareHelper::Create(remoteObj_, SETTING_URI_PROXY, SETTINGS_DATA_EXT_URI);
    if (ret == DATA_SHARE_READY) {
        return helper;
    } else if (ret == DATA_SHARE_NOT_READY) {
        FI_HILOGE("Create data_share helper failed, uri proxy:%{public}s", SETTING_URI_PROXY.c_str());
        return nullptr;
    }
    FI_HILOGD("Data_share create unknown");
    return nullptr;
}

bool PullThrowListener::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper)
{
    CHKPF(helper);
    if (!helper->Release()) {
        FI_HILOGE("Release helper fail");
        return false;
    }
    return true;
}

int32_t PullThrowListener::GetIntValue(const std::string &key, int32_t &value)
{
    int64_t valueLong;
    int32_t ret = GetLongValue(key, valueLong);
    if (ret != ERR_OK) {
        FI_HILOGE("GetIntValue fail");
        return ret;
    }
    value = static_cast<int32_t>(valueLong);
    return ERR_OK;
}

int32_t PullThrowListener::GetLongValue(const std::string &key, int64_t &value)
{
    std::string valueStr;
    int32_t ret = GetStringValue(key, valueStr);
    if (ret != ERR_OK) {
        FI_HILOGE("GetLongValue fail");
        return ret;
    }
    value = static_cast<int64_t>(strtoll(valueStr.c_str(), nullptr, DECEM_BASE));
    return ERR_OK;
}

int32_t PullThrowListener::GetStringValue(const std::string &key, std::string &value)
{
    FI_HILOGI("enter");
    auto helper = CreateDataShareHelper();
    std::vector<std::string> columns = {"VALUE"};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("KEYWORD", key);
    Uri uri((SETTING_URI_PROXY + "&key=" + key));
    CHKPR(helper, RET_ERR);
    auto resultSet = helper->Query(uri, predicates, columns);
    const int32_t index = 0;
    if (resultSet == nullptr) {
        FI_HILOGE("resultSet is nullptr");
        ReleaseDataShareHelper(helper);
        return RET_ERR;
    }
    resultSet->GoToRow(index);
    int32_t ret = resultSet->GetString(index, value);
    if (ret != ERR_OK) {
        FI_HILOGE("GetString failed, ret:%{public}d", ret);
        resultSet->Close();
        ReleaseDataShareHelper(helper);
        return ret;
    }
    resultSet->Close();
    ReleaseDataShareHelper(helper);
    return ERR_OK;
}

bool PullThrowListener::RegisterVKObserver(const sptr<VKObserver> &observer)
{
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    remoteObj_ = sm->GetSystemAbility(MSDP_DEVICESTATUS_SERVICE_ID);
    if (observer == nullptr) {
        FI_HILOGD("observer is nullptr");
        return false;
    }
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return false;
    }
    Uri uriFeedback((SETTING_URI_PROXY + "&key=" + SETTING_VK_KEY));
    helper->RegisterObserver(uriFeedback, observer);
    helper->NotifyChange(uriFeedback);

    ReleaseDataShareHelper(helper);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    FI_HILOGI("Succeed to register observer of virtual keyboard");
    return true;
}

void PullThrowListener::VKObserver::OnChange()
{
    if (update_ != nullptr) {
        update_();
    }
}

void PullThrowListener::VKObserver::SetUpdateFunc(const UpdateFunc &func)
{
    update_ = func;
}

sptr<PullThrowListener::VKObserver> PullThrowListener::CreateVKObserver(const VKObserver::UpdateFunc &func)
{
    sptr<VKObserver> observer = new VKObserver();
    if (observer == nullptr) {
        FI_HILOGD("observer is null");
        return observer;
    }
    observer->SetUpdateFunc(func);
    return observer;
}

bool PullThrowListener::RegisterPullThrowListener()
{
    if (!RegisterFoldStatusListener() || !RegisterScreenMagneticStateListener()) {
        FI_HILOGD("unable to register FoldStatusListener or MagneticStateListener");
        return false;
    }
    return true;
}

bool PullThrowListener::RegisterVKListener()
{
    const VKObserver::UpdateFunc updateFunc = [&]() {
        GetIntValue(SETTING_VK_KEY, obstatusVk_);
        if (obstatusVk_ == 1) {
            FI_HILOGI("VK UpdateFunc Thorw cancel; obstatusVk_: %{public}d", obstatusVk_);
            CHKPV(manager_);
            manager_->OnDragCancel(manager_->currentPointerEvent_);
        } else {
            FI_HILOGD("Virtual keyboard obstatusVk_: %{public}d", obstatusVk_);
        }
    };
    auto VKobserver_ = CreateVKObserver(updateFunc);
    if (!RegisterVKObserver(VKobserver_)) {
        FI_HILOGD("unable to register VK listener");
        return false;
    }
    return true;
}

bool PullThrowListener::ValidateThrowConditions()
{
    oldFoldStatus_ = Rosen::DisplayManager::GetInstance().GetFoldStatus();
    FI_HILOGI("Listener params: VK Status=%{public}d, MK Status=%{public}d, Fold Status=%{public}u",
              obstatusVk_, currentMagneticState_, oldFoldStatus_);
    return !(obstatusVk_ == 1 || oldFoldStatus_ != Rosen::FoldStatus::HALF_FOLD || currentMagneticState_);
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
