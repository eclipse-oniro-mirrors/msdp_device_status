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

#include "accesstoken_kit.h"
#include "intention_service.h"

#include <ipc_skeleton.h>
#include <string_ex.h>
#include <tokenid_kit.h>
#include <xcollie/xcollie.h>
#include <xcollie/xcollie_define.h>

#include "devicestatus_define.h"
#include "sequenceable_drag_visible.h"

#undef LOG_TAG
#define LOG_TAG "IntentionService"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

IntentionService::IntentionService(IContext *context)
    : context_(context), socketServer_(context),
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    cooperate_(context),
#endif // OHOS_BUILD_ENABLE_COORDINATION
    drag_(context), dumper_(context, stationary_), boomerangDumper_(context, boomerang_)
{
    (void) context_;
}

// public

/*
* If new code needs to be added, please place it in the corresponding locations according to the business type:
  Public/Cooperate/Drag/Boomerang/Stationary.
*/

CallingContext IntentionService::GetCallingContext()
{
    CallingContext context {
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    return context;
}

void IntentionService::PrintCallingContext(const CallingContext &context)
{
    FI_HILOGI("fullTokenId:%{public}" PRIu64 ", tokenId:%{public}d, uid:%{public}d, pid:%{public}d",
        context.fullTokenId, context.tokenId, context.uid, context.pid);
}

int32_t IntentionService::PostSyncTask(TaskProtoType task)
{
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetDelegateTasks().PostSyncTask([&] {
        CHKPR(task, RET_ERR);
        return task();
    });
    if (ret != RET_OK) {
        FI_HILOGE("PostSyncTask failed, ret:%{public}d", ret);
    }
    return ret;
}

// Socket

ErrCode IntentionService::Socket(const std::string& programName, int32_t moduleType, int& socketFd, int32_t& tokenType)
{
    CALL_INFO_TRACE;
    CallingContext context = GetCallingContext();
    PrintCallingContext(context);
    return PostSyncTask([this, &context, &programName, moduleType, &socketFd, &tokenType] {
        return socketServer_.Socket(context, programName, moduleType, socketFd, tokenType);
    });
}

// Cooperate

ErrCode IntentionService::EnableCooperate(int32_t userData)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, userData] {
        return cooperate_.EnableCooperate(context, userData);
    });
#else
    CooperateNoticeLite notice {
        .pid = context.pid,
        .msgId = MessageId::COORDINATION_MESSAGE,
        .userData = userData,
        .msg = CoordinationMessage::PREPARE
    };
    NotifyCooperateMessage(notice);
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::DisableCooperate(int32_t userData)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, userData] {
        return cooperate_.DisableCooperate(context, userData);
    });
#else
    CooperateNoticeLite notice {
        .pid = context.pid,
        .msgId = MessageId::COORDINATION_MESSAGE,
        .userData = userData,
        .msg = CoordinationMessage::UNPREPARE
    };
    NotifyCooperateMessage(notice);
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::StartCooperate(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
    bool checkPermission)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, &remoteNetworkId, userData, startDeviceId, checkPermission] {
        return cooperate_.StartCooperate(context, remoteNetworkId, userData, startDeviceId, checkPermission);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::StartCooperateWithOptions(const std::string& remoteNetworkId, int32_t userData,
    int32_t startDeviceId, bool checkPermission, const SequenceableCooperateOptions& options)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, &remoteNetworkId, userData, startDeviceId, checkPermission, &options] {
        return cooperate_.StartCooperateWithOptions(context, remoteNetworkId, userData,
            startDeviceId, options.options_);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::StopCooperate(int32_t userData, bool isUnchained, bool checkPermission)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, userData, isUnchained, checkPermission] {
        return cooperate_.StopCooperate(context, userData, isUnchained, checkPermission);
    });
#else
    CooperateNoticeLite notice {
        .pid = context.pid,
        .msgId = MessageId::COORDINATION_MESSAGE,
        .userData = userData,
        .networkId = "",
        .msg = CoordinationMessage::DEACTIVATE_SUCCESS,
        .errCode = 0
    };
    NotifyCooperateMessage(notice);
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::RegisterCooperateListener()
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context] {
        return cooperate_.RegisterCooperateListener(context);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::UnregisterCooperateListener()
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context] {
        return cooperate_.UnregisterCooperateListener(context);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::RegisterHotAreaListener(int32_t userData, bool checkPermission)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, userData, checkPermission] {
        return cooperate_.RegisterHotAreaListener(context, userData, checkPermission);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::UnregisterHotAreaListener()
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context] {
        return cooperate_.UnregisterHotAreaListener(context);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::RegisterMouseEventListener(const std::string& networkId)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, &networkId] {
        return cooperate_.RegisterMouseEventListener(context, networkId);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::UnregisterMouseEventListener(const std::string& networkId)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, &networkId] {
        return cooperate_.UnregisterMouseEventListener(context, networkId);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::GetCooperateStateSync(const std::string& udid, bool& state)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, &udid, &state] {
        return cooperate_.GetCooperateStateSync(context, udid, state);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::GetCooperateStateAsync(const std::string& networkId, int32_t userData, bool isCheckPermission)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, &networkId, userData, isCheckPermission] {
        return cooperate_.GetCooperateStateAsync(context, networkId, userData, isCheckPermission);
    });
#else
    CooperateStateNoticeLite notice {
        .pid = context.pid,
        .msgId = MessageId::COORDINATION_GET_STATE,
        .userData = userData,
        .state = false,
    };
    NotifyCooperateState(notice);
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::SetDamplingCoefficient(uint32_t direction, double coefficient)
{
    CallingContext context = GetCallingContext();
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return PostSyncTask([this, &context, direction, coefficient] {
        return cooperate_.SetDamplingCoefficient(context, direction, coefficient);
    });
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

ErrCode IntentionService::StartDrag(const SequenceableDragData &sequenceableDragData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &sequenceableDragData] {
        return drag_.StartDrag(context, sequenceableDragData.dragData_);
    });
}

ErrCode IntentionService::StopDrag(const SequenceableDragResult &sequenceableDragResult)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &sequenceableDragResult] {
        return drag_.StopDrag(context, sequenceableDragResult.dragDropResult_);
    });
}

ErrCode IntentionService::EnableInternalDropAnimation(const std::string &animationInfo)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.EnableInternalDropAnimation(context, animationInfo);
    });
}

ErrCode IntentionService::AddDraglistener(bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, isJsCaller] {
        return drag_.AddDraglistener(context, isJsCaller);
    });
}

ErrCode IntentionService::RemoveDraglistener(bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, isJsCaller] {
        return drag_.RemoveDraglistener(context, isJsCaller);
    });
}

ErrCode IntentionService::AddSubscriptListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context] {
        return drag_.AddSubscriptListener(context);
    });
}

ErrCode IntentionService::RemoveSubscriptListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context] {
        return drag_.RemoveSubscriptListener(context);
    });
}

ErrCode IntentionService::SetDragWindowVisible(const SequenceableDragVisible &sequenceableDragVisible)
{
    return PostSyncTask([this, &sequenceableDragVisible] {
        return drag_.SetDragWindowVisible(sequenceableDragVisible.dragVisibleParam_.visible,
            sequenceableDragVisible.dragVisibleParam_.isForce, sequenceableDragVisible.dragVisibleParam_.rsTransaction);
    });
}

ErrCode IntentionService::UpdateDragStyle(int32_t style, int32_t eventId)
{
    CallingContext context = GetCallingContext();
    DragCursorStyle cursorStyle = static_cast<DragCursorStyle>(style);
    return PostSyncTask([this, &context, cursorStyle, eventId] {
        return drag_.UpdateDragStyle(context, cursorStyle, eventId);
    });
}

ErrCode IntentionService::UpdateShadowPic(const std::shared_ptr<PixelMap>& pixelMap, int32_t x, int32_t y)
{
    ShadowInfo shadowInfo;
    shadowInfo.pixelMap = pixelMap;
    shadowInfo.x = x;
    shadowInfo.y = y;
    return PostSyncTask([this, &shadowInfo] {
        return drag_.UpdateShadowPic(shadowInfo);
    });
}

ErrCode IntentionService::GetDragTargetPid(int32_t &targetPid)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &targetPid] {
        return drag_.GetDragTargetPid(context, targetPid);
    });
}

ErrCode IntentionService::GetUdKey(std::string &udKey)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &udKey] {
        return drag_.GetUdKey(context, udKey);
    });
}

ErrCode IntentionService::GetShadowOffset(int32_t &offsetX, int32_t &offsetY, int32_t &width, int32_t &height)
{
    ShadowOffset shadowOffset;
    return PostSyncTask([this, &shadowOffset, &offsetX, &offsetY, &width, &height] {
        int32_t ret = drag_.GetShadowOffset(shadowOffset);
        if (ret != RET_OK) {
            return ret;
        }
        offsetX = shadowOffset.offsetX;
        offsetY = shadowOffset.offsetY;
        width = shadowOffset.width;
        height = shadowOffset.height;
        return ret;
    });
}

ErrCode IntentionService::GetDragData(SequenceableDragData &sequenceableDragData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &sequenceableDragData] {
        return drag_.GetDragData(context, sequenceableDragData.dragData_);
    });
}

ErrCode IntentionService::UpdatePreviewStyle(const SequenceablePreviewStyle &sequenceablePreviewStyle)
{
    return PostSyncTask([this, &sequenceablePreviewStyle] {
        return drag_.UpdatePreviewStyle(sequenceablePreviewStyle.previewStyle_);
    });
}

ErrCode IntentionService::UpdatePreviewStyleWithAnimation(
    const SequenceablePreviewAnimation &sequenceablePreviewAnimation)
{
    return PostSyncTask([this, &sequenceablePreviewAnimation] {
        return drag_.UpdatePreviewStyleWithAnimation(
            sequenceablePreviewAnimation.previewStyle_, sequenceablePreviewAnimation.previewAnimation_);
    });
}

ErrCode IntentionService::RotateDragWindowSync(const SequenceableRotateWindow &sequenceableRotateWindow)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &sequenceableRotateWindow] {
        return drag_.RotateDragWindowSync(context, sequenceableRotateWindow.rsTransaction_);
    });
}

ErrCode IntentionService::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    CHKPR(context_, RET_ERR);
    CallingContext context = GetCallingContext();
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, context, displayId, screenId] {
        return this->drag_.SetDragWindowScreenId(context, displayId, screenId);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post async task failed");
    }
    return ret;
}

ErrCode IntentionService::GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &summarys, isJsCaller] {
        return drag_.GetDragSummary(context, summarys, isJsCaller);
    });
}

ErrCode IntentionService::GetDragSummaryInfo(SequenceableDragSummaryInfo &sequenceableDragSummaryInfo)
{
    return PostSyncTask([this, &sequenceableDragSummaryInfo] {
        DragSummaryInfo dragSummaryInfo;
        int32_t ret = drag_.GetDragSummaryInfo(dragSummaryInfo);
        if (ret != RET_OK) {
            return ret;
        }
        sequenceableDragSummaryInfo.SetDragSummaryInfo(dragSummaryInfo);
        return RET_OK;
    });
}

ErrCode IntentionService::SetDragSwitchState(bool enable, bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, enable, isJsCaller] {
        return drag_.SetDragSwitchState(context, enable, isJsCaller);
    });
}

ErrCode IntentionService::SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, enable, &pkgName, isJsCaller] {
       return drag_.SetAppDragSwitchState(context, enable, pkgName, isJsCaller);
    });
}

ErrCode IntentionService::GetDragState(int32_t& dragState)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &dragState] {
        DragState state = static_cast<DragState>(dragState);
        auto ret = drag_.GetDragState(context, state);
        dragState = static_cast<int32_t>(state);
        return ret;
    });
}

ErrCode IntentionService::EnableUpperCenterMode(bool enable)
{
    return PostSyncTask([this, enable] {
        return drag_.EnableUpperCenterMode(enable);
    });
}

ErrCode IntentionService::GetDragAction(int32_t &dragAction)
{
    return PostSyncTask([this, &dragAction] {
        DragAction action = static_cast<DragAction>(dragAction);
        auto ret = drag_.GetDragAction(action);
        dragAction = static_cast<int32_t>(action);
        return ret;
    });
}

ErrCode IntentionService::GetExtraInfo(std::string &extraInfo)
{
    return PostSyncTask([this, &extraInfo] {
       return drag_.GetExtraInfo(extraInfo);
    });
}

ErrCode IntentionService::AddPrivilege(const std::string &signature,
    const SequenceableDragEventData &sequenceableDragEventData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, signature, sequenceableDragEventData] {
       return drag_.AddPrivilege(context, signature, sequenceableDragEventData.dragEventData_);
    });
}

ErrCode IntentionService::EraseMouseIcon()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context] {
       return drag_.EraseMouseIcon(context);
    });
}

ErrCode IntentionService::SetMouseDragMonitorState(bool state)
{
    return PostSyncTask([this, state] {
        return drag_.SetMouseDragMonitorState(state);
    });
}

ErrCode IntentionService::SetDraggableState(bool state)
{
    return PostSyncTask([this, state] {
       return drag_.SetDraggableState(state);
    });
}

ErrCode IntentionService::GetAppDragSwitchState(bool &state)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &state] {
       return drag_.GetAppDragSwitchState(context, state);
    });
}

ErrCode IntentionService::SetDraggableStateAsync(bool state, int64_t downTime)
{
    return PostSyncTask([this, state, downTime] {
       return drag_.SetDraggableStateAsync(state, downTime);
    });
}

ErrCode IntentionService::GetDragBundleInfo(std::string &bundleName, bool &state)
{
    return PostSyncTask([this, &bundleName, &state] {
        DragBundleInfo dragBundleInfo;
        if (int32_t ret = drag_.GetDragBundleInfo(dragBundleInfo); ret != RET_OK) {
            return ret;
        }
        bundleName = dragBundleInfo.bundleName;
        state = dragBundleInfo.isCrossDevice;
        return RET_OK;
    });
}

ErrCode IntentionService::IsDragStart(bool &isStart)
{
    return PostSyncTask([this, &isStart] {
        return drag_.IsDragStart(isStart);
    });
}

// Boomerang

ErrCode IntentionService::SubscribeCallback(int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& subCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, type, &bundleName, &subCallback] {
       return boomerang_.SubscribeCallback(context, type, bundleName, subCallback);
    });
}

ErrCode IntentionService::UnsubscribeCallback(int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& unsubCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, type, &bundleName, &unsubCallback] {
       return boomerang_.UnsubscribeCallback(context, type, bundleName, unsubCallback);
    });
}

ErrCode IntentionService::NotifyMetadataBindingEvent(const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& notifyCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &bundleName, &notifyCallback] {
       return boomerang_.NotifyMetadataBindingEvent(context, bundleName, notifyCallback);
    });
}

ErrCode IntentionService::SubmitMetadata(const std::string& metaData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &metaData] {
       return boomerang_.SubmitMetadata(context, metaData);
    });
}

ErrCode IntentionService::BoomerangEncodeImage(const std::shared_ptr<PixelMap>& pixelMap, const std::string& metaData,
    const sptr<IRemoteBoomerangCallback>& encodeCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &pixelMap, &metaData, &encodeCallback] {
       return boomerang_.BoomerangEncodeImage(context, pixelMap, metaData, encodeCallback);
    });
}

ErrCode IntentionService::BoomerangDecodeImage(const std::shared_ptr<PixelMap>& pixelMap,
    const sptr<IRemoteBoomerangCallback>& decodeCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &pixelMap, &decodeCallback] {
       return boomerang_.BoomerangDecodeImage(context, pixelMap, decodeCallback);
    });
}

// Stationary

ErrCode IntentionService::SubscribeStationaryCallback(int32_t type, int32_t event,
    int32_t latency, const sptr<IRemoteDevStaCallback> &subCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, type, event, latency, &subCallback] {
       return stationary_.SubscribeStationaryCallback(context, type, event, latency, subCallback);
    });
}

ErrCode IntentionService::UnsubscribeStationaryCallback(int32_t type, int32_t event,
    const sptr<IRemoteDevStaCallback> &unsubCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, type, event, &unsubCallback] {
       return stationary_.UnsubscribeStationaryCallback(context, type, event, unsubCallback);
    });
}

ErrCode IntentionService::GetDeviceStatusData(int32_t type, int32_t &replyType, int32_t &replyValue)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, type, &replyType, &replyValue] {
       return stationary_.GetDeviceStatusData(context, type, replyType, replyValue);
    });
}

ErrCode IntentionService::GetDevicePostureDataSync(SequenceablePostureData &data)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &data] {
        DevicePostureData rawPostureData;
        int32_t ret = stationary_.GetDevicePostureDataSync(context, rawPostureData);
        if (ret != RET_OK) {
            return ret;
        }
        data.SetPostureData(rawPostureData);
        return RET_OK;
    });
}

ErrCode IntentionService::GetPageContent(const OnScreen::SequenceableContentOption &contentOption,
    OnScreen::SequenceablePageContent &pageContent)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &contentOption, &pageContent] {
        OnScreen::PageContent rawPageContent;
        int32_t ret = onScreen_.GetPageContent(context, contentOption.option_, rawPageContent);
        if (ret != RET_OK) {
            return ret;
        }
        pageContent.pageContent_ = rawPageContent;
        return RET_OK;
    });
}

ErrCode IntentionService::SendControlEvent(const OnScreen::SequenceableControlEvent &event)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, &event] {
        return onScreen_.SendControlEvent(context, event.controlEvent_);
    });
}

ErrCode IntentionService::ListenLiveBroadcast()
{
    return PostSyncTask([this] {
        return onScreen_.ListenLiveBroadcast();
    });
}

int32_t IntentionService::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    if (fd < 0) {
        FI_HILOGE("fd is invalid, %{public}d", fd);
        return RET_ERR;
    }
    return onScreen_.Dump(fd, args);
}

ErrCode IntentionService::RegisterScreenEventCallback(int32_t windowId, const std::string& event,
    const sptr<OnScreen::IRemoteOnScreenCallback>& onScreenCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, windowId, &event, &onScreenCallback] {
        return onScreen_.RegisterScreenEventCallback(context, windowId, event, onScreenCallback);
    });
}

ErrCode IntentionService::UnregisterScreenEventCallback(int32_t windowId, const std::string& event,
    const sptr<OnScreen::IRemoteOnScreenCallback>& onScreenCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, windowId, &event, &onScreenCallback] {
        return onScreen_.UnregisterScreenEventCallback(context, windowId, event, onScreenCallback);
    });
}

ErrCode IntentionService::IsParallelFeatureEnabled(int32_t windowId, int32_t& outStatus)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, windowId, &outStatus] {
        return onScreen_.IsParallelFeatureEnabled(context, windowId, outStatus);
    });
}

int32_t IntentionService::GetLiveStatus()
{
    return PostSyncTask([this] {
        return onScreen_.GetLiveStatus();
    });
}

ErrCode IntentionService::RegisterAwarenessCallback(const OnScreen::SequenceableOnscreenAwarenessCap& cap,
    const sptr<OnScreen::IRemoteOnScreenCallback>& onScreenCallback,
    const OnScreen::SequenceableOnscreenAwarenessOption& awarenessOption)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, cap, onScreenCallback, awarenessOption] {
        return onScreen_.RegisterAwarenessCallback(context, cap.cap_, onScreenCallback, awarenessOption.option_);
    });
}

ErrCode IntentionService::UnregisterAwarenessCallback(const OnScreen::SequenceableOnscreenAwarenessCap& cap,
    const sptr<OnScreen::IRemoteOnScreenCallback>& onScreenCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, cap, onScreenCallback] {
        return onScreen_.UnregisterAwarenessCallback(context, cap.cap_, onScreenCallback);
    });
}

ErrCode IntentionService::Trigger(const OnScreen::SequenceableOnscreenAwarenessCap& cap,
    const OnScreen::SequenceableOnscreenAwarenessOption& awarenessOption,
    OnScreen::SequenceableOnscreenAwarenessInfo& info)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([this, &context, cap, awarenessOption, &info] {
        OnScreen::OnscreenAwarenessInfo awarenessInfo;
        int32_t ret = onScreen_.Trigger(context, cap.cap_, awarenessOption.option_, awarenessInfo);
        if (ret != RET_OK) {
            return ret;
        }
        info.info_ = awarenessInfo;
        return RET_OK;
    });
}

bool IntentionService::CheckCooperatePermission(CallingContext &context)
{
    CALL_DEBUG_ENTER;
    Security::AccessToken::AccessTokenID callerToken = context.tokenId;
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken,
        COOPERATE_PERMISSION);
    return result == Security::AccessToken::PERMISSION_GRANTED;
}

bool IntentionService::IsSystemServiceCalling(CallingContext &context)
{
    const auto flag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if (flag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        flag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        FI_HILOGD("system service calling, flag:%{public}u", flag);
        return true;
    }
    return false;
}

bool IntentionService::IsSystemCalling(CallingContext &context)
{
    if (IsSystemServiceCalling(context)) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}

int32_t IntentionService::CheckPermission(CallingContext &context)
{
    if (!IsSystemCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!CheckCooperatePermission(context)) {
        FI_HILOGE("The caller has no COOPERATE_MANAGER permission");
        return COMMON_PERMISSION_CHECK_ERROR;
    }
    return RET_OK;
}

#ifndef OHOS_BUILD_ENABLE_COORDINATION
void IntentionService::NotifyCooperateMessage(const CooperateNoticeLite &notice)
{
    CHKPV(context_);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(notice.pid);
    if (session == nullptr) {
        FI_HILOGD("session is null");
        return;
    }
    NetPacket pkt(notice.msgId);
    pkt << notice.userData << notice.networkId << static_cast<int32_t>(notice.msg) << notice.errCode;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
    }
}

void IntentionService::NotifyCooperateState(const CooperateStateNoticeLite &notice)
{
    CALL_INFO_TRACE;
    CHKPV(context_);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(notice.pid);
    CHKPV(session);
    NetPacket pkt(notice.msgId);
    pkt << notice.userData << notice.state << static_cast<int32_t>(notice.errCode);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
        return;
    }
}
#endif // OHOS_BUILD_ENABLE_COORDINATION
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
