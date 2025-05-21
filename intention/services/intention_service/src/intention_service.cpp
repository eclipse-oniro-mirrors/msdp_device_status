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

#include "intention_service.h"

#include <ipc_skeleton.h>
#include <string_ex.h>
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
    : context_(context), socketServer_(context), cooperate_(context), drag_(context), dumper_(context, stationary_),
    boomerangDumper_(context, boomerang_)
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
    return PostSyncTask([&] {
        return socketServer_.Socket(context, programName, moduleType, socketFd, tokenType);
    });
}

// Cooperate

ErrCode IntentionService::EnableCooperate(int32_t userData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.EnableCooperate(context, userData);
    });
}

ErrCode IntentionService::DisableCooperate(int32_t userData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.DisableCooperate(context, userData);
    });
}

ErrCode IntentionService::StartCooperate(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
    bool checkPermission)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.StartCooperate(context, remoteNetworkId, userData, startDeviceId, checkPermission);
    });
}

ErrCode IntentionService::StopCooperate(int32_t userData, bool isUnchained, bool checkPermission)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.StopCooperate(context, userData, isUnchained, checkPermission);
    });
}

ErrCode IntentionService::RegisterCooperateListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.RegisterCooperateListener(context);
    });
}

ErrCode IntentionService::UnregisterCooperateListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.UnregisterCooperateListener(context);
    });
}

ErrCode IntentionService::RegisterHotAreaListener(int32_t userData, bool checkPermission)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.RegisterHotAreaListener(context, userData, checkPermission);
    });
}

ErrCode IntentionService::UnregisterHotAreaListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.UnregisterHotAreaListener(context);
    });
}

ErrCode IntentionService::RegisterMouseEventListener(const std::string& networkId)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.RegisterMouseEventListener(context, networkId);
    });
}

ErrCode IntentionService::UnregisterMouseEventListener(const std::string& networkId)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.UnregisterMouseEventListener(context, networkId);
    });
}

ErrCode IntentionService::GetCooperateStateSync(const std::string& udid, bool& state)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.GetCooperateStateSync(context, udid, state);
    });
}

ErrCode IntentionService::GetCooperateStateAsync(const std::string& networkId, int32_t userData, bool isCheckPermission)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.GetCooperateStateAsync(context, networkId, userData, isCheckPermission);
    });
}

ErrCode IntentionService::SetDamplingCoefficient(uint32_t direction, double coefficient)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return cooperate_.SetDamplingCoefficient(context, direction, coefficient);
    });
}

ErrCode IntentionService::StartDrag(const SequenceableDragData &sequenceableDragData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.StartDrag(context, sequenceableDragData.dragData_);
    });
}

ErrCode IntentionService::StopDrag(const SequenceableDragResult &sequenceableDragResult)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.StopDrag(context, sequenceableDragResult.dragDropResult_);
    });
}

ErrCode IntentionService::AddDraglistener(bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.AddDraglistener(context, isJsCaller);
    });
}

ErrCode IntentionService::RemoveDraglistener(bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.RemoveDraglistener(context, isJsCaller);
    });
}

ErrCode IntentionService::AddSubscriptListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.AddSubscriptListener(context);
    });
}

ErrCode IntentionService::RemoveSubscriptListener()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.RemoveSubscriptListener(context);
    });
}

ErrCode IntentionService::SetDragWindowVisible(const SequenceableDragVisible &sequenceableDragVisible)
{
    return PostSyncTask([&] {
        return drag_.SetDragWindowVisible(sequenceableDragVisible.dragVisibleParam_.visible,
            sequenceableDragVisible.dragVisibleParam_.isForce, sequenceableDragVisible.dragVisibleParam_.rsTransaction);
    });
}

ErrCode IntentionService::UpdateDragStyle(int32_t style, int32_t eventId)
{
    CallingContext context = GetCallingContext();
    DragCursorStyle cursorStyle = static_cast<DragCursorStyle>(style);
    return PostSyncTask([&] {
        return drag_.UpdateDragStyle(context, cursorStyle, eventId);
    });
}

ErrCode IntentionService::UpdateShadowPic(const std::shared_ptr<PixelMap>& pixelMap, int32_t x, int32_t y)
{
    ShadowInfo shadowInfo;
    shadowInfo.pixelMap = pixelMap;
    shadowInfo.x = x;
    shadowInfo.y = y;
    return PostSyncTask([&] {
        return drag_.UpdateShadowPic(shadowInfo);
    });
}

ErrCode IntentionService::GetDragTargetPid(int32_t &targetPid)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.GetDragTargetPid(context, targetPid);
    });
}

ErrCode IntentionService::GetUdKey(std::string &udKey)
{
    return PostSyncTask([&] {
        return drag_.GetUdKey(udKey);
    });
}

ErrCode IntentionService::GetShadowOffset(int32_t &offsetX, int32_t &offsetY, int32_t &width, int32_t &height)
{
    ShadowOffset shadowOffset;
    return PostSyncTask([&] {
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
    return PostSyncTask([&] {
        return drag_.GetDragData(context, sequenceableDragData.dragData_);
    });
}

ErrCode IntentionService::UpdatePreviewStyle(const SequenceablePreviewStyle &sequenceablePreviewStyle)
{
    return PostSyncTask([&] {
        return drag_.UpdatePreviewStyle(sequenceablePreviewStyle.previewStyle_);
    });
}

ErrCode IntentionService::UpdatePreviewStyleWithAnimation(
    const SequenceablePreviewAnimation &sequenceablePreviewAnimation)
{
    return PostSyncTask([&] {
        return drag_.UpdatePreviewStyleWithAnimation(
            sequenceablePreviewAnimation.previewStyle_, sequenceablePreviewAnimation.previewAnimation_);
    });
}

ErrCode IntentionService::RotateDragWindowSync(const SequenceableRotateWindow &sequenceableRotateWindow)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.RotateDragWindowSync(context, sequenceableRotateWindow.rsTransaction_);
    });
}

ErrCode IntentionService::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.SetDragWindowScreenId(context, displayId, screenId);
    });
}

ErrCode IntentionService::GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.GetDragSummary(context, summarys, isJsCaller);
    });
}

ErrCode IntentionService::SetDragSwitchState(bool enable, bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
        return drag_.SetDragSwitchState(context, enable, isJsCaller);
    });
}

ErrCode IntentionService::SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return drag_.SetAppDragSwitchState(context, enable, pkgName, isJsCaller);
    });
}

ErrCode IntentionService::GetDragState(int32_t& dragState)
{
    return PostSyncTask([&] {
        DragState state = static_cast<DragState>(dragState);
        auto ret = drag_.GetDragState(state);
        dragState = static_cast<int32_t>(state);
        return ret;
    });
}

ErrCode IntentionService::EnableUpperCenterMode(bool enable)
{
    return PostSyncTask([&] {
        return drag_.EnableUpperCenterMode(enable);
    });
}

ErrCode IntentionService::GetDragAction(int32_t &dragAction)
{
    return PostSyncTask([&] {
        DragAction action = static_cast<DragAction>(dragAction);
        auto ret = drag_.GetDragAction(action);
        dragAction = static_cast<int32_t>(action);
        return ret;
    });
}

ErrCode IntentionService::GetExtraInfo(std::string &extraInfo)
{
    return PostSyncTask([&] {
       return drag_.GetExtraInfo(extraInfo);
    });
}

ErrCode IntentionService::AddPrivilege()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return drag_.AddPrivilege(context);
    });
}

ErrCode IntentionService::EraseMouseIcon()
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return drag_.EraseMouseIcon(context);
    });
}

ErrCode IntentionService::SetMouseDragMonitorState(bool state)
{
    return PostSyncTask([&] {
        return drag_.SetMouseDragMonitorState(state);
    });
}

ErrCode IntentionService::SetDraggableState(bool state)
{
    return PostSyncTask([&] {
       return drag_.SetDraggableState(state);
    });
}
ErrCode IntentionService::GetAppDragSwitchState(bool &state)
{
    return PostSyncTask([&] {
       return drag_.GetAppDragSwitchState(state);
    });
}

ErrCode IntentionService::SetDraggableStateAsync(bool state, int64_t downTime)
{
    return PostSyncTask([&] {
       return drag_.SetDraggableStateAsync(state, downTime);
    });
}

ErrCode IntentionService::GetDragBundleInfo(std::string &bundleName, bool &state)
{
    return PostSyncTask([&] {
        DragBundleInfo dragBundleInfo;
        if (int32_t ret = drag_.GetDragBundleInfo(dragBundleInfo); ret != RET_OK) {
            return ret;
        }
        bundleName = dragBundleInfo.bundleName;
        state = dragBundleInfo.isCrossDevice;
        return RET_OK;
    });
}

// Boomerang

ErrCode IntentionService::SubscribeCallback(int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& subCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return boomerang_.SubscribeCallback(context, type, bundleName, subCallback);
    });
}

ErrCode IntentionService::UnsubscribeCallback(int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& unsubCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return boomerang_.UnsubscribeCallback(context, type, bundleName, unsubCallback);
    });
}

ErrCode IntentionService::NotifyMetadataBindingEvent(const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& notifyCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return boomerang_.NotifyMetadataBindingEvent(context, bundleName, notifyCallback);
    });
}

ErrCode IntentionService::SubmitMetadata(const std::string& metaData)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return boomerang_.SubmitMetadata(context, metaData);
    });
}

ErrCode IntentionService::BoomerangEncodeImage(const std::shared_ptr<PixelMap>& pixelMap, const std::string& metaData,
    const sptr<IRemoteBoomerangCallback>& encodeCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return boomerang_.BoomerangEncodeImage(context, pixelMap, metaData, encodeCallback);
    });
}

ErrCode IntentionService::BoomerangDecodeImage(const std::shared_ptr<PixelMap>& pixelMap,
    const sptr<IRemoteBoomerangCallback>& decodeCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return boomerang_.BoomerangDecodeImage(context, pixelMap, decodeCallback);
    });
}

// Stationary

ErrCode IntentionService::SubscribeStationaryCallback(int32_t type, int32_t event,
    int32_t latency, const sptr<IRemoteDevStaCallback> &subCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return stationary_.SubscribeStationaryCallback(context, type, event, latency, subCallback);
    });
}

ErrCode IntentionService::UnsubscribeStationaryCallback(int32_t type, int32_t event,
    const sptr<IRemoteDevStaCallback> &unsubCallback)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return stationary_.UnsubscribeStationaryCallback(context, type, event, unsubCallback);
    });
}

ErrCode IntentionService::GetDeviceStatusData(int32_t type, int32_t &replyType, int32_t &replyValue)
{
    CallingContext context = GetCallingContext();
    return PostSyncTask([&] {
       return stationary_.GetDeviceStatusData(context, type, replyType, replyValue);
    });
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
