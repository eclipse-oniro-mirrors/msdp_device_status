/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "intention_manager.h"

#include "display_manager.h"

#include "devicestatus_define.h"
#include "drag_data.h"

#undef LOG_TAG
#define LOG_TAG "IntentionManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t INDEX_FOLDED { 0 };
constexpr int32_t INDEX_EXPAND { 1 };
constexpr size_t POLICY_VEC_SIZE { 2 };
const std::string SCREEN_ROTATION { "1" };
} // namespace

IntentionManager::IntentionManager()
{
}

IntentionManager::~IntentionManager()
{
    client_.reset();
}

void IntentionManager::InitClient()
{
    CALL_DEBUG_ENTER;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (client_ != nullptr) {
            return;
        }
        client_ = std::make_unique<SocketClient>();
        InitMsgHandler();
        client_->RegisterConnectedFunction([this] {
            this->OnConnected();
        });
        client_->RegisterDisconnectedFunction([this] {
            this->OnDisconnected();
        });
        client_->Start();
    }
    GetRotatePolicy(isScreenRotation_, foldRotatePolicys_);
}

void IntentionManager::InitMsgHandler()
{
    CALL_DEBUG_ENTER;
    std::map<MessageId, std::function<int32_t(const StreamClient&, NetPacket&)>> funs {
#ifdef OHOS_BUILD_ENABLE_COORDINATION
        {MessageId::COORDINATION_ADD_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnCoordinationListener(client, pkt);
        }},
        {MessageId::COORDINATION_MESSAGE, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnCoordinationMessage(client, pkt);
        }},
        {MessageId::COORDINATION_GET_STATE, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnCoordinationState(client, pkt);
        }},
        {MessageId::HOT_AREA_ADD_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnHotAreaListener(client, pkt);
        }},
        {MessageId::MOUSE_LOCATION_ADD_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnMouseLocationListener(client, pkt);
        }},
#endif // OHOS_BUILD_ENABLE_COORDINATION

        {MessageId::DRAG_NOTIFY_RESULT, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnNotifyResult(client, pkt);
        }},
        {MessageId::DRAG_STATE_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnStateChangedMessage(client, pkt);
        }},
        {MessageId::DRAG_NOTIFY_HIDE_ICON, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnNotifyHideIcon(client, pkt);
        }},
        {MessageId::DRAG_STYLE_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnDragStyleChangedMessage(client, pkt);
        }}
    };
    CHKPV(client_);
    for (auto &[id, cb] : funs) {
        if (!client_->RegisterEvent(id, cb)) {
            FI_HILOGI("RegistER event handler msg:%{public}d already exists", id);
        }
    }
}

int32_t IntentionManager::SubscribeCallback(Type type, ActivityEvent event, ReportLatencyNs latency,
    sptr<IRemoteDevStaCallback> callback)
{
    InitClient();
    return stationary_.SubscribeCallback(type, event, latency, callback);
}

int32_t IntentionManager::UnsubscribeCallback(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback)
{
    InitClient();
    return stationary_.UnsubscribeCallback(type, event, callback);
}

int32_t IntentionManager::GetDevicePostureDataSync(DevicePostureData &data)
{
    return stationary_.GetDevicePostureDataSync(data);
}

int32_t IntentionManager::SubscribeCallback(BoomerangType type, std::string bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    return boomerang_.SubscribeCallback(type, bundleName, callback);
}
 
int32_t IntentionManager::UnsubscribeCallback(BoomerangType type, std::string bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    return boomerang_.UnsubscribeCallback(type, bundleName, callback);
}
 
int32_t IntentionManager::NotifyMetadataBindingEvent(std::string bundleName, sptr<IRemoteBoomerangCallback> callback)
{
    return boomerang_.NotifyMetadataBindingEvent(bundleName, callback);
}
 
int32_t IntentionManager::SubmitMetadata(std::string metadata)
{
    return boomerang_.SubmitMetadata(metadata);
}
 
int32_t IntentionManager::BoomerangEncodeImage(std::shared_ptr<Media::PixelMap> pixelMap, std::string matedata,
    sptr<IRemoteBoomerangCallback> callback)
{
    return boomerang_.BoomerangEncodeImage(pixelMap, matedata, callback);
}
 
int32_t IntentionManager::BoomerangDecodeImage(std::shared_ptr<Media::PixelMap> pixelMap,
    sptr<IRemoteBoomerangCallback> callback)
{
    return boomerang_.BoomerangDecodeImage(pixelMap, callback);
}

Data IntentionManager::GetDeviceStatusData(const Type type)
{
    return stationary_.GetDeviceStatusData(type);
}

int32_t IntentionManager::RegisterCoordinationListener(
    std::shared_ptr<ICoordinationListener> listener, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.RegisterListener(listener, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UnregisterCoordinationListener(
    std::shared_ptr<ICoordinationListener> listener, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return cooperate_.UnregisterListener(listener, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::PrepareCoordination(CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Enable(callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UnprepareCoordination(CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Disable(callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::ActivateCoordination(const std::string &remoteNetworkId, int32_t startDeviceId,
    CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Start(remoteNetworkId, startDeviceId, callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(remoteNetworkId);
    (void)(startDeviceId);
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::ActivateCooperateWithOptions(const std::string &remoteNetworkId,
    int32_t startDeviceId, CooperateMsgInfoCallback callback, const CooperateOptions &options)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.StartWithOptions(remoteNetworkId, startDeviceId, callback, options);
#else
    FI_HILOGW("Coordination does not support");
    (void)(remoteNetworkId);
    (void)(startDeviceId);
    (void)(callback);
    (void)(options);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::DeactivateCoordination(bool isUnchained,
    CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Stop(isUnchained, callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::GetCoordinationState(
    const std::string &networkId, std::function<void(bool)> callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.GetCooperateState(networkId, callback, isCompatible);
#else
    (void)(networkId);
    (void)(callback);
    (void)(isCompatible);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::GetCoordinationState(const std::string &udId, bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.GetCooperateState(udId, state);
#else
    (void)(udId);
    (void)(state);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::RegisterEventListener(const std::string &networkId, std::shared_ptr<IEventListener> listener)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.RegisterEventListener(networkId, listener);
#else
    (void)(networkId);
    (void)(listener);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UnregisterEventListener(const std::string &networkId,
    std::shared_ptr<IEventListener> listener)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.UnregisterEventListener(networkId, listener);
#else
    (void)(networkId);
    (void)(listener);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::SetDamplingCoefficient(uint32_t direction, double coefficient)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.SetDamplingCoefficient(direction, coefficient);
#else
    (void)(direction);
    (void)(coefficient);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UpdateDragStyle(DragCursorStyle style, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdateDragStyle(style, eventId);
}

int32_t IntentionManager::StartDrag(const DragData &dragData, std::shared_ptr<IStartDragListener> listener)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return drag_.StartDrag(dragData, listener);
}

int32_t IntentionManager::StopDrag(const DragDropResult &dropResult)
{
    CALL_DEBUG_ENTER;
    return drag_.StopDrag(dropResult);
}

int32_t IntentionManager::GetDragTargetPid()
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragTargetPid();
}

int32_t IntentionManager::GetUdKey(std::string &udKey)
{
    CALL_DEBUG_ENTER;
    return drag_.GetUdKey(udKey);
}

int32_t IntentionManager::AddDraglistener(DragListenerPtr listener, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return drag_.AddDraglistener(listener, isJsCaller);
}

int32_t IntentionManager::RemoveDraglistener(DragListenerPtr listener, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    return drag_.RemoveDraglistener(listener, isJsCaller);
}

int32_t IntentionManager::AddSubscriptListener(SubscriptListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return drag_.AddSubscriptListener(listener);
}

int32_t IntentionManager::RemoveSubscriptListener(SubscriptListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    return drag_.RemoveSubscriptListener(listener);
}

int32_t IntentionManager::SetDragWindowVisible(
    bool visible, bool isForce, const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDragWindowVisible(visible, isForce, rsTransaction);
}

int32_t IntentionManager::GetShadowOffset(ShadowOffset &shadowOffset)
{
    CALL_DEBUG_ENTER;
    return drag_.GetShadowOffset(shadowOffset);
}

int32_t IntentionManager::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdateShadowPic(shadowInfo);
}

int32_t IntentionManager::GetDragData(DragData &dragData)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragData(dragData);
}

int32_t IntentionManager::GetDragState(DragState &dragState)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragState(dragState);
}

int32_t IntentionManager::GetDragAction(DragAction &dragAction)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragAction(dragAction);
}

int32_t IntentionManager::GetExtraInfo(std::string &extraInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.GetExtraInfo(extraInfo);
}

int32_t IntentionManager::AddHotAreaListener(std::shared_ptr<IHotAreaListener> listener)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.AddHotAreaListener(listener);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::RemoveHotAreaListener(std::shared_ptr<IHotAreaListener> listener)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return cooperate_.RemoveHotAreaListener(listener);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdatePreviewStyle(previewStyle);
}

int32_t IntentionManager::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
    const PreviewAnimation &animation)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdatePreviewStyleWithAnimation(previewStyle, animation);
}

int32_t IntentionManager::RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CALL_DEBUG_ENTER;
    if (isScreenRotation_) {
        FI_HILOGW("Screen rotation, not need rotate drag window");
        return RET_OK;
    }
    if (Rosen::DisplayManager::GetInstance().IsFoldable()) {
        if ((foldRotatePolicys_.empty()) || (foldRotatePolicys_.size() < POLICY_VEC_SIZE)) {
            FI_HILOGE("foldRotatePolicys_ is invalid");
            return drag_.RotateDragWindowSync(rsTransaction);
        }
        Rosen::FoldStatus foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
        if (IsSecondaryDevice()) {
            bool isExpand = (foldStatus == Rosen::FoldStatus::EXPAND || foldStatus == Rosen::FoldStatus::HALF_FOLD ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_EXPAND ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_HALF_FOLDED ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_HALF_FOLDED_WITH_SECOND_EXPAND ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_HALF_FOLDED_WITH_SECOND_HALF_FOLDED);
            bool isFold = (foldStatus == Rosen::FoldStatus::FOLDED ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_FOLDED_WITH_SECOND_EXPAND ||
                foldStatus == Rosen::FoldStatus::FOLD_STATE_FOLDED_WITH_SECOND_HALF_FOLDED);
            if ((isExpand && (foldRotatePolicys_[INDEX_EXPAND] == SCREEN_ROTATION)) ||
                (isFold && (foldRotatePolicys_[INDEX_FOLDED] == SCREEN_ROTATION))) {
                FI_HILOGD("Secondary device Full display rotation, not need rotate drag window");
                return RET_OK;
            }
        } else {
            if ((((foldStatus == Rosen::FoldStatus::EXPAND) || (foldStatus == Rosen::FoldStatus::HALF_FOLD)) &&
                (foldRotatePolicys_[INDEX_EXPAND] == SCREEN_ROTATION)) ||
                ((foldStatus == Rosen::FoldStatus::FOLDED) && (foldRotatePolicys_[INDEX_FOLDED] == SCREEN_ROTATION))) {
                FI_HILOGD("Full display rotation, not need rotate drag window");
                return RET_OK;
            }
        }
    }
    return drag_.RotateDragWindowSync(rsTransaction);
}

int32_t IntentionManager::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDragWindowScreenId(displayId, screenId);
}

int32_t IntentionManager::GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragSummary(summarys, isJsCaller);
}

int32_t IntentionManager::SetDragSwitchState(bool enable, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDragSwitchState(enable, isJsCaller);
}

int32_t IntentionManager::SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    return drag_.SetAppDragSwitchState(enable, pkgName, isJsCaller);
}

int32_t IntentionManager::EnterTextEditorArea(bool enable)
{
    CALL_DEBUG_ENTER;
    return drag_.EnableUpperCenterMode(enable);
}

int32_t IntentionManager::AddPrivilege()
{
    CALL_DEBUG_ENTER;
    return drag_.AddPrivilege();
}

int32_t IntentionManager::EraseMouseIcon()
{
    CALL_DEBUG_ENTER;
    return drag_.EraseMouseIcon();
}

int32_t IntentionManager::SetMouseDragMonitorState(bool state)
{
    CALL_DEBUG_ENTER;
    return drag_.SetMouseDragMonitorState(state);
}

void IntentionManager::OnConnected()
{
    CALL_DEBUG_ENTER;

    drag_.OnConnected();
    cooperate_.OnConnected();
    stationary_.OnConnected();
    onScreen_.OnConnected();
}

void IntentionManager::OnDisconnected()
{
    CALL_DEBUG_ENTER;
    drag_.OnDisconnected();
    cooperate_.OnDisconnected();
}

int32_t IntentionManager::SetDraggableState(bool state)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDraggableState(state);
}

int32_t IntentionManager::GetAppDragSwitchState(bool &state)
{
    CALL_DEBUG_ENTER;
    return drag_.GetAppDragSwitchState(state);
}

void IntentionManager::SetDraggableStateAsync(bool state, int64_t downTime)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDraggableStateAsync(state, downTime);
}

int32_t IntentionManager::GetDragBundleInfo(DragBundleInfo &dragBundleInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragBundleInfo(dragBundleInfo);
}

int32_t IntentionManager::EnableInternalDropAnimation(const std::string &animationInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.EnableInternalDropAnimation(animationInfo);
}

bool IntentionManager::IsDragStart()
{
    CALL_DEBUG_ENTER;
    return drag_.IsDragStart();
}

int32_t IntentionManager::GetDragSummaryInfo(DragSummaryInfo &dragSummaryInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragSummaryInfo(dragSummaryInfo);
}

int32_t IntentionManager::GetPageContent(const OnScreen::ContentOption& option, OnScreen::PageContent& pageContent)
{
    CALL_DEBUG_ENTER;
    return onScreen_.GetPageContent(option, pageContent);
}

int32_t IntentionManager::SendControlEvent(const OnScreen::ControlEvent& event)
{
    CALL_DEBUG_ENTER;
    return onScreen_.SendControlEvent(event);
}

int32_t IntentionManager::RegisterScreenEventCallback(int32_t windowId, std::string event,
    sptr<OnScreen::IRemoteOnScreenCallback> callback)
{
    CALL_DEBUG_ENTER;
    return onScreen_.RegisterScreenEventCallback(windowId, event, callback);
}

int32_t IntentionManager::UnregisterScreenEventCallback(int32_t windowId, std::string event,
    sptr<OnScreen::IRemoteOnScreenCallback> callback)
{
    CALL_DEBUG_ENTER;
    return onScreen_.UnregisterScreenEventCallback(windowId, event, callback);
}

int32_t IntentionManager::IsParallelFeatureEnabled(int32_t windowId, int32_t& outStatus)
{
    CALL_DEBUG_ENTER;
    return onScreen_.IsParallelFeatureEnabled(windowId, outStatus);
}

int32_t IntentionManager::GetLiveStatus()
{
    CALL_DEBUG_ENTER;
    return onScreen_.GetLiveStatus();
}

int32_t IntentionManager::RegisterAwarenessCallback(const OnScreen::AwarenessCap& cap,
    sptr<OnScreen::IRemoteOnScreenCallback> callback, const OnScreen::AwarenessOptions& option)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return onScreen_.RegisterAwarenessCallback(cap, callback, option);
}

int32_t IntentionManager::UnregisterAwarenessCallback(const OnScreen::AwarenessCap& cap,
    sptr<OnScreen::IRemoteOnScreenCallback> callback)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return onScreen_.UnregisterAwarenessCallback(cap, callback);
}

int32_t IntentionManager::Trigger(const OnScreen::AwarenessCap& cap, const OnScreen::AwarenessOptions& option,
    OnScreen::OnscreenAwarenessInfo& info)
{
    CALL_DEBUG_ENTER;
    return onScreen_.Trigger(cap, option, info);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
