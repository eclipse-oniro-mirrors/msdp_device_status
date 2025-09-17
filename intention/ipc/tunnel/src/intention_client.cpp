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

#include "intention_client.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iremote_broker.h"
#include "iremote_object.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "IntentionClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

constexpr int32_t TIME_WAIT_FOR_DS_MS { 1000 };
std::shared_ptr<IntentionClient> IntentionClient::instance_ = std::make_shared<IntentionClient>();

IntentionClient *IntentionClient::GetInstance()
{
    return instance_.get();
}

IntentionClient::~IntentionClient()
{
    std::lock_guard lock(mutex_);
    if (devicestatusProxy_ != nullptr) {
        auto remoteObject = devicestatusProxy_->AsObject();
        if (remoteObject != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

ErrCode IntentionClient::Connect()
{
    CALL_INFO_TRACE;
    std::lock_guard lock(mutex_);
    if (devicestatusProxy_ != nullptr) {
        return RET_OK;
    }

    sptr<ISystemAbilityManager> sa = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPR(sa, E_DEVICESTATUS_GET_SYSTEM_ABILITY_MANAGER_FAILED);

    sptr<IRemoteObject> remoteObject = sa->CheckSystemAbility(MSDP_DEVICESTATUS_SERVICE_ID);
    CHKPR(remoteObject, E_DEVICESTATUS_GET_SERVICE_FAILED);

    deathRecipient_ = sptr<DeathRecipient>::MakeSptr(shared_from_this());
    CHKPR(deathRecipient_, ERR_NO_MEMORY);

    if (remoteObject->IsProxyObject()) {
        if (!remoteObject->AddDeathRecipient(deathRecipient_)) {
            FI_HILOGE("Add death recipient to DeviceStatus service failed");
            return E_DEVICESTATUS_ADD_DEATH_RECIPIENT_FAILED;
        }
    }

    devicestatusProxy_ = iface_cast<IIntention>(remoteObject);
    FI_HILOGI("Connecting IntentionService success");
    return RET_OK;
}

int32_t IntentionClient::Socket(const std::string& programName, int32_t moduleType, int& socketFd, int32_t& tokenType)
{
    CALL_INFO_TRACE;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->Socket(programName, moduleType, socketFd, tokenType); ret != RET_OK) {
        FI_HILOGE("proxy::Socket fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::EnableCooperate(int32_t userData)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->EnableCooperate(userData); ret != RET_OK) {
        FI_HILOGE("proxy::EnableCooperate fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::DisableCooperate(int32_t userData)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->DisableCooperate(userData); ret != RET_OK) {
        FI_HILOGE("proxy::DisableCooperate fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::StartCooperate(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
    bool checkPermission)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->StartCooperate(remoteNetworkId, userData, startDeviceId, checkPermission);
        ret != RET_OK) {
        FI_HILOGE("proxy::StartCooperate fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::StartCooperateWithOptions(const std::string &remoteNetworkId,
    int32_t userData, int32_t startDeviceId, bool checkPermission, const CooperateOptions &options)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceableCooperateOptions sequenceableCooperateOptions(options);
    if (int32_t ret = devicestatusProxy_->StartCooperateWithOptions(remoteNetworkId, userData,
        startDeviceId, checkPermission, sequenceableCooperateOptions); ret != RET_OK) {
        FI_HILOGE("proxy::StartCooperateWithOptions fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::StopCooperate(int32_t userData, bool isUnchained, bool checkPermission)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->StopCooperate(userData, isUnchained, checkPermission);
        ret != RET_OK) {
        FI_HILOGE("proxy::StopCooperate fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::RegisterCooperateListener()
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->RegisterCooperateListener();
        ret != RET_OK) {
        FI_HILOGE("proxy::RegisterCooperateListener fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UnregisterCooperateListener()
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->UnregisterCooperateListener();
        ret != RET_OK) {
        FI_HILOGE("proxy::UnregisterCooperateListener fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::RegisterHotAreaListener(int32_t userData, bool checkPermission)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->RegisterHotAreaListener(userData, checkPermission);
        ret != RET_OK) {
        FI_HILOGE("proxy::RegisterHotAreaListener fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UnregisterHotAreaListener(int32_t userData, bool checkPermission)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->UnregisterHotAreaListener();
        ret != RET_OK) {
        FI_HILOGE("proxy::UnregisterHotAreaListener fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::RegisterMouseEventListener(const std::string& networkId)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->RegisterMouseEventListener(networkId);
        ret != RET_OK) {
        FI_HILOGE("proxy::RegisterMouseEventListener fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UnregisterMouseEventListener(const std::string& networkId)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->UnregisterMouseEventListener(networkId);
        ret != RET_OK) {
        FI_HILOGE("proxy::UnregisterMouseEventListener fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetCooperateStateSync(const std::string& udid, bool& state)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetCooperateStateSync(udid, state);
        ret != RET_OK) {
        FI_HILOGE("proxy::GetCooperateStateSync fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetCooperateStateAsync(const std::string& networkId, int32_t userData, bool isCheckPermission)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetCooperateStateAsync(networkId, userData, isCheckPermission);
        ret != RET_OK) {
        FI_HILOGE("proxy::GetCooperateStateAsync fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetDamplingCoefficient(uint32_t direction, double coefficient)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetDamplingCoefficient(direction, coefficient);
        ret != RET_OK) {
        FI_HILOGE("proxy::SetDamplingCoefficient fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::StartDrag(const DragData &dragData)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceableDragData sequenceableDragData(dragData);
    if (int32_t ret = devicestatusProxy_->StartDrag(sequenceableDragData); ret != RET_OK) {
        FI_HILOGE("proxy::StartDrag fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::StopDrag(const DragDropResult &dropResult)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceableDragResult sequenceableDragResult(dropResult);
    if (int32_t ret = devicestatusProxy_->StopDrag(sequenceableDragResult); ret != RET_OK) {
        FI_HILOGE("proxy::StopDrag fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::EnableInternalDropAnimation(const std::string &animationInfo)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    int32_t ret = devicestatusProxy_->EnableInternalDropAnimation(animationInfo);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::EnableInternalDropAnimation fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::AddDraglistener(bool isJsCaller)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    return devicestatusProxy_->AddDraglistener(isJsCaller);
}

int32_t IntentionClient::RemoveDraglistener(bool isJsCaller)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    return devicestatusProxy_->RemoveDraglistener(isJsCaller);
}

int32_t IntentionClient::AddSubscriptListener()
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    return devicestatusProxy_->AddSubscriptListener();
}

int32_t IntentionClient::RemoveSubscriptListener()
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    return devicestatusProxy_->RemoveSubscriptListener();
}

int32_t IntentionClient::SetDragWindowVisible(bool visible, bool isForce,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    DragVisibleParam dragVisibleParam;
    dragVisibleParam.visible = visible;
    dragVisibleParam.isForce = isForce;
    dragVisibleParam.rsTransaction = rsTransaction;
    SequenceableDragVisible sequenceableDragVisible(dragVisibleParam);
    if (int32_t ret = devicestatusProxy_->SetDragWindowVisible(sequenceableDragVisible); ret != RET_OK) {
        FI_HILOGE("proxy::SetDragWindowVisible fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UpdateDragStyle(DragCursorStyle style, int32_t eventId = -1)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->UpdateDragStyle(static_cast<int32_t>(style), eventId); ret != RET_OK) {
        FI_HILOGE("proxy::UpdateDragStyle fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    return devicestatusProxy_->UpdateShadowPic(shadowInfo.pixelMap, shadowInfo.x, shadowInfo.y);
}

int32_t IntentionClient::GetDragTargetPid(int32_t &targetPid)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    return devicestatusProxy_->GetDragTargetPid(targetPid);
}

int32_t IntentionClient::GetUdKey(std::string &udKey)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetUdKey(udKey); ret != RET_OK) {
        FI_HILOGE("proxy::GetUdKey fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetShadowOffset(ShadowOffset &shadowOffset)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    int32_t offsetX = -1;
    int32_t offsetY = -1;
    int32_t width = -1;
    int32_t height = -1;
    if (int32_t ret = devicestatusProxy_->GetShadowOffset(offsetX, offsetY, width, height); ret != RET_OK) {
        FI_HILOGE("proxy::GetShadowOffset fail");
        return ret;
    }
    shadowOffset.offsetX = offsetX;
    shadowOffset.offsetY = offsetY;
    shadowOffset.width = width;
    shadowOffset.height = height;
    return RET_OK;
}

int32_t IntentionClient::GetDragData(DragData &dragData)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceableDragData sequenceableDragData(dragData);
    if (int32_t ret = devicestatusProxy_->GetDragData(sequenceableDragData); ret != RET_OK) {
        FI_HILOGE("proxy::GetDragData fail");
        return ret;
    }
    dragData = sequenceableDragData.dragData_;
    return RET_OK;
}

int32_t IntentionClient::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceablePreviewStyle sequenceablePreviewStyle(previewStyle);
    if (int32_t ret = devicestatusProxy_->UpdatePreviewStyle(sequenceablePreviewStyle); ret != RET_OK) {
        FI_HILOGE("proxy::UpdatePreviewStyle fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
    const PreviewAnimation &animation)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceablePreviewAnimation sequenceablePreviewAnimation(previewStyle, animation);
    if (int32_t ret = devicestatusProxy_->UpdatePreviewStyleWithAnimation(sequenceablePreviewAnimation);
        ret != RET_OK) {
        FI_HILOGE("proxy::UpdatePreviewStyleWithAnimation fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceableRotateWindow sequenceableRotateWindow(rsTransaction);
    if (int32_t ret = devicestatusProxy_->RotateDragWindowSync(sequenceableRotateWindow);
        ret != RET_OK) {
        FI_HILOGE("proxy::RotateDragWindowSync fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetDragWindowScreenId(displayId, screenId); ret != RET_OK) {
        FI_HILOGE("proxy::SetDragWindowScreenId fail");
        return ret;
    }
    deathDisplayId_.store(displayId);
    deathScreenId_.store(screenId);
    return RET_OK;
}

void ResetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    FI_HILOGI("displayId:%{public}" PRId64 ", screenId:%{public}" PRId64 "", displayId, screenId);
    if (displayId == UINT64_MAX && screenId == UINT64_MAX) {
        FI_HILOGE("The display ID and screen ID are default maximun values");
        return;
    }
    std::thread([this, displayId, screenId]() {
        std::this_thread::sleep_for(std::chrono::microseconds(TIME_WAIT_FOR_DS_MS));
        this->SetDragWindowScreenId(displayId, screenId);
    }).detach();
}

int32_t IntentionClient::GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetDragSummary(summarys, isJsCaller); ret != RET_OK) {
        FI_HILOGE("proxy::GetDragSummary fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetDragSwitchState(bool enable, bool isJsCaller)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetDragSwitchState(enable, isJsCaller); ret != RET_OK) {
        FI_HILOGE("proxy::SetDragSwitchState fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetAppDragSwitchState(enable, pkgName, isJsCaller); ret != RET_OK) {
        FI_HILOGE("proxy::SetAppDragSwitchState fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetDragState(DragState &dragState)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    int32_t state { -1 };
    if (int32_t ret = devicestatusProxy_->GetDragState(state); ret != RET_OK) {
        FI_HILOGE("proxy::GetDragState fail");
        return ret;
    }
    dragState = static_cast<DragState>(state);
    return RET_OK;
}

int32_t IntentionClient::IsDragStart(bool &isStart)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    auto ret = devicestatusProxy_->IsDragStart(isStart);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::IsDragStart fail, ret =  %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SubscribeCallback(int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& subCallback)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SubscribeCallback(type, bundleName, subCallback); ret != RET_OK) {
        FI_HILOGE("proxy::SubscribeCallback fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UnsubscribeCallback(int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& unsubCallback)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->UnsubscribeCallback(type, bundleName, unsubCallback); ret != RET_OK) {
        FI_HILOGE("proxy::UnsubscribeCallback fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::NotifyMetadataBindingEvent(const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& notifyCallback)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->NotifyMetadataBindingEvent(bundleName, notifyCallback); ret != RET_OK) {
        FI_HILOGE("proxy::NotifyMetadataBindingEvent fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SubmitMetadata(const std::string& metadata)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SubmitMetadata(metadata); ret != RET_OK) {
        FI_HILOGE("proxy::SubmitMetadata fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::BoomerangEncodeImage(const std::shared_ptr<PixelMap>& pixelMap, const std::string& metadata,
    const sptr<IRemoteBoomerangCallback>& encodeCallback)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->BoomerangEncodeImage(pixelMap, metadata, encodeCallback); ret != RET_OK) {
        FI_HILOGE("proxy::BoomerangEncodeImage fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::BoomerangDecodeImage(const std::shared_ptr<PixelMap>& pixelMap,
    const sptr<IRemoteBoomerangCallback>& decodeCallback)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->BoomerangDecodeImage(pixelMap, decodeCallback); ret != RET_OK) {
        FI_HILOGE("proxy::BoomerangDecodeImage fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetDragSummaryInfo(DragSummaryInfo &dragSummaryInfo)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    SequenceableDragSummaryInfo sequenceableDragSummaryInfo(dragSummaryInfo);
    CHKPR(devicestatusProxy_, RET_ERR);
    auto ret = devicestatusProxy_->GetDragSummaryInfo(sequenceableDragSummaryInfo);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::GetDragSummaryInfo fail, ret =  %{public}d", ret);
        return ret;
    }
    sequenceableDragSummaryInfo.GetDragSummaryInfo(dragSummaryInfo);
    return RET_OK;
}

int32_t IntentionClient::EnableUpperCenterMode(bool enable)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->EnableUpperCenterMode(enable); ret != RET_OK) {
        FI_HILOGE("proxy::EnableUpperCenterMode fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetDragAction(DragAction &dragAction)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    int32_t action { -1 };
    if (int32_t ret = devicestatusProxy_->GetDragAction(action); ret != RET_OK) {
        FI_HILOGE("proxy::GetDragAction fail");
        return ret;
    }
    dragAction = static_cast<DragAction>(action);
    return RET_OK;
}

int32_t IntentionClient::GetExtraInfo(std::string &extraInfo)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetExtraInfo(extraInfo); ret != RET_OK) {
        FI_HILOGE("proxy::GetExtraInfo fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::AddPrivilege()
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->AddPrivilege(); ret != RET_OK) {
        FI_HILOGE("proxy::AddPrivilege fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::EraseMouseIcon()
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->EraseMouseIcon(); ret != RET_OK) {
        FI_HILOGE("proxy::EraseMouseIcon fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetMouseDragMonitorState(bool state)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetMouseDragMonitorState(state); ret != RET_OK) {
        FI_HILOGE("proxy::SetMouseDragMonitorState fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetDraggableState(bool state)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetDraggableState(state); ret != RET_OK) {
        FI_HILOGE("proxy::SetDraggableState fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetAppDragSwitchState(bool &state)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetAppDragSwitchState(state); ret != RET_OK) {
        FI_HILOGE("proxy::GetAppDragSwitchState fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::SetDraggableStateAsync(bool state, int64_t downTime)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SetDraggableStateAsync(state, downTime); ret != RET_OK) {
        FI_HILOGE("proxy::SetDraggableStateAsync fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetDragBundleInfo(DragBundleInfo &dragBundleInfo)
{
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    DragBundleInfo bundelInfo;
    if (int32_t ret = devicestatusProxy_->GetDragBundleInfo(bundelInfo.bundleName, bundelInfo.isCrossDevice);
        ret != RET_OK) {
        FI_HILOGE("proxy::GetDragBundleInfo fail");
        return ret;
    }
    dragBundleInfo = bundelInfo;
    return RET_OK;
}

int32_t IntentionClient::SubscribeStationaryCallback(int32_t type, int32_t event,
    int32_t latency, const sptr<IRemoteDevStaCallback> &subCallback)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not subscribe stationary callback");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->SubscribeStationaryCallback(type, event, latency, subCallback);
        ret != RET_OK) {
        FI_HILOGE("proxy::SubscribeStationaryCallback fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::UnsubscribeStationaryCallback(int32_t type, int32_t event,
    const sptr<IRemoteDevStaCallback> &unsubCallback)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not unsubscribe stationary callback");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->UnsubscribeStationaryCallback(type, event, unsubCallback);
        ret != RET_OK) {
        FI_HILOGE("proxy::UnsubscribeStationaryCallback fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetDeviceStatusData(int32_t type, int32_t &replyType, int32_t &replyValue)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not Get device status data");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    if (int32_t ret = devicestatusProxy_->GetDeviceStatusData(type, replyType, replyValue);
        ret != RET_OK) {
        FI_HILOGE("proxy::GetDeviceStatusData fail");
        return ret;
    }
    return RET_OK;
}

int32_t IntentionClient::GetDevicePostureDataSync(DevicePostureData &postureData)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("cannot get device status data");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    SequenceablePostureData seqData(postureData);
    int32_t ret = devicestatusProxy_->GetDevicePostureDataSync(seqData);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::GetDevicePostureDataSync fail");
        return ret;
    }
    postureData = seqData.GetPostureData();
    return RET_OK;
}

int32_t IntentionClient::GetPageContent(const OnScreen::ContentOption& option, OnScreen::PageContent& pageContent)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("can not get proxy");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    OnScreen::SequenceableContentOption seqOption(option);
    OnScreen::SequenceablePageContent seqPageContent(pageContent);
    int32_t ret = devicestatusProxy_->GetPageContent(seqOption, seqPageContent);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::GetPageContent fail");
        return ret;
    }
    pageContent = seqPageContent.pageContent_;
    return RET_OK;
}

int32_t IntentionClient::SendControlEvent(const OnScreen::ControlEvent& event)
{
    CALL_DEBUG_ENTER;
    if (Connect() != RET_OK) {
        FI_HILOGE("can not get proxy");
        return RET_ERR;
    }
    std::lock_guard lock(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    OnScreen::SequenceableControlEvent seqEvent(event);
    int32_t ret = devicestatusProxy_->SendControlEvent(seqEvent);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::SendControlEvent fail");
        return ret;
    }
    return RET_OK;
}

void IntentionClient::ResetProxy(const wptr<IRemoteObject> &remote)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPV(devicestatusProxy_);
    auto serviceRemote = devicestatusProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        devicestatusProxy_ = nullptr;
    }
}

IntentionClient::DeathRecipient::DeathRecipient(std::shared_ptr<IntentionClient> parent)
    : parent_(parent)
{}

void IntentionClient::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<IntentionClient> parent = parent_.lock();
    CHKPV(parent);
    CHKPV(remote);
    parent->ResetProxy(remote);
    FI_HILOGD("Recv death notice");
    parent->ResetDragWindowScreenId(parent->deathDisplayId_.load(), parent->deathScreenId_.load());
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
