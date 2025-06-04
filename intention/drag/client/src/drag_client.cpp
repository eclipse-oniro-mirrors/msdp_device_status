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

#include "drag_client.h"

#include "default_params.h"
#include "drag_params.h"
#include "devicestatus_define.h"
#include "devicestatus_proto.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "DragClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t DragClient::StartDrag(const DragData &dragData, std::shared_ptr<IStartDragListener> listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    if (dragData.shadowInfos.empty()) {
        FI_HILOGE("shadowInfos is empty");
        return ERR_INVALID_VALUE;
    }
    for (const auto& shadowInfo : dragData.shadowInfos) {
        CHKPR(shadowInfo.pixelMap, RET_ERR);
        if ((shadowInfo.x > 0) || (shadowInfo.y > 0) ||
            (shadowInfo.x < -shadowInfo.pixelMap->GetWidth()) ||
            (shadowInfo.y < -shadowInfo.pixelMap->GetHeight())) {
            FI_HILOGE("Invalid parameter, shadowInfox:%{private}d, shadowInfoy:%{private}d",
                shadowInfo.x, shadowInfo.y);
            return RET_ERR;
        }
    }
    if ((dragData.dragNum <= 0) || (dragData.buffer.size() > MAX_BUFFER_SIZE) ||
        (dragData.displayX < 0) || (dragData.displayY < 0)) {
        FI_HILOGE("Start drag, invalid argument, dragNum:%{public}d, bufferSize:%{public}zu, "
            "displayX:%{private}d, displayY:%{private}d",
            dragData.dragNum, dragData.buffer.size(), dragData.displayX, dragData.displayY);
        return RET_ERR;
    }
    {
        std::lock_guard<std::mutex> guard(mtx_);
        startDragListener_ = listener;
    }
    int32_t ret = INTENTION_CLIENT->StartDrag(dragData);
    if (ret != RET_OK) {
        FI_HILOGE("StartDrag fail");
    }
    return ret;
}

int32_t DragClient::GetDragState(DragState &dragState)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetDragState(dragState);
    if (ret != RET_OK) {
        FI_HILOGE("GetDragState fail");
    }
    return ret;
}

int32_t DragClient::StopDrag(const DragDropResult &dropResult)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->StopDrag(dropResult);
    if (ret != RET_OK) {
        FI_HILOGE("StopDrag fail");
    }
    return ret;
}

int32_t DragClient::EnableInternalDropAnimation(const std::string &animationInfo)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->EnableInternalDropAnimation(animationInfo);
    if (ret != RET_OK) {
        FI_HILOGE("EnableInternalDropAnimation fail");
    }
    return ret;
}

int32_t DragClient::UpdateDragStyle(DragCursorStyle style, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    if ((style < DragCursorStyle::DEFAULT) || (style > DragCursorStyle::MOVE)) {
        FI_HILOGE("Invalid style:%{public}d", static_cast<int32_t>(style));
        return RET_ERR;
    }
    int32_t ret = INTENTION_CLIENT->UpdateDragStyle(style, eventId);
    if (ret != RET_OK) {
        FI_HILOGE("UpdateDragStyle fail");
    }
    return ret;
}

int32_t DragClient::GetDragTargetPid()
{
    CALL_DEBUG_ENTER;
    int32_t targetPid = -1;
    int32_t ret = INTENTION_CLIENT->GetDragTargetPid(targetPid);
    if (ret != RET_OK) {
        FI_HILOGE("GetDragTargetPid fail");
    }
    return targetPid;
}

int32_t DragClient::GetUdKey(std::string &udKey)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetUdKey(udKey);
    if (ret != RET_OK) {
        FI_HILOGE("GetUdKey fail");
    }
    return ret;
}

int32_t DragClient::AddDraglistener(DragListenerPtr listener, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    std::lock_guard<std::mutex> guard(mtx_);
    if (dragListeners_.find(listener) != dragListeners_.end()) {
        return RET_OK;
    }
    if (!hasRegistered_) {
        FI_HILOGI("Start drag listening");
        int32_t ret = INTENTION_CLIENT->AddDraglistener(isJsCaller);
        if (ret != RET_OK) {
            FI_HILOGE("AddDraglistener fail");
            return ret;
        }
        hasRegistered_ = true;
    }
    dragListeners_.insert(listener);
    return RET_OK;
}

int32_t DragClient::RemoveDraglistener(DragListenerPtr listener, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (listener == nullptr) {
        dragListeners_.clear();
    } else {
        dragListeners_.erase(listener);
    }
    if (hasRegistered_ && dragListeners_.empty()) {
        hasRegistered_ = false;
        FI_HILOGI("Stop drag listening");
        int32_t ret = INTENTION_CLIENT->RemoveDraglistener(isJsCaller);
        if (ret != RET_OK) {
            FI_HILOGE("RemoveDraglistener fail");
            return ret;
        }
    }
    return RET_OK;
}
int32_t DragClient::AddSubscriptListener(SubscriptListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscriptListeners_.find(listener) != subscriptListeners_.end()) {
        return RET_OK;
    }
    if (!hasSubscriptRegistered_) {
        FI_HILOGI("Start subscript listening");
        int32_t ret = INTENTION_CLIENT->AddSubscriptListener();
        if (ret != RET_OK) {
            FI_HILOGE("AddSubscriptListener fail");
            return ret;
        }
        hasSubscriptRegistered_ = true;
    }
    subscriptListeners_.insert(listener);
    return RET_OK;
}

int32_t DragClient::RemoveSubscriptListener(SubscriptListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (listener == nullptr) {
        subscriptListeners_.clear();
    } else {
        subscriptListeners_.erase(listener);
    }
    if (hasSubscriptRegistered_ && subscriptListeners_.empty()) {
        hasSubscriptRegistered_ = false;
        FI_HILOGI("Stop subscript listening");
        int32_t ret = INTENTION_CLIENT->RemoveSubscriptListener();
        if (ret != RET_OK) {
            FI_HILOGE("RemoveSubscriptListener fail");
            return ret;
        }
    }
    return RET_OK;
}

int32_t DragClient::SetDragWindowVisible(bool visible, bool isForce,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->SetDragWindowVisible(visible, isForce, rsTransaction);
    if (ret != RET_OK) {
        FI_HILOGE("SetDragWindowVisible fail");
    }
    return ret;
}

int32_t DragClient::GetShadowOffset(ShadowOffset &shadowOffset)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetShadowOffset(shadowOffset);
    if (ret != RET_OK) {
        FI_HILOGE("GetShadowOffset fail");
    }
    return ret;
}

int32_t DragClient::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    CALL_DEBUG_ENTER;
    CHKPR(shadowInfo.pixelMap, RET_ERR);
    if ((shadowInfo.x > 0) || (shadowInfo.y > 0) ||
        (shadowInfo.x < -shadowInfo.pixelMap->GetWidth()) ||
        (shadowInfo.y < -shadowInfo.pixelMap->GetHeight())) {
        FI_HILOGE("Invalid parameter, shadowInfox:%{private}d, shadowInfoy:%{private}d",
            shadowInfo.x, shadowInfo.y);
        return RET_ERR;
    }
    int32_t ret = INTENTION_CLIENT->UpdateShadowPic(shadowInfo);
    if (ret != RET_OK) {
        FI_HILOGE("UpdateShadowPic fail");
    }
    return ret;
}

int32_t DragClient::GetDragData(DragData &dragData)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetDragData(dragData);
    if (ret != RET_OK) {
        FI_HILOGE("GetDragData fail");
    }
    return ret;
}

int32_t DragClient::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->UpdatePreviewStyle(previewStyle);
    if (ret != RET_OK) {
        FI_HILOGE("UpdatePreviewStyle fail");
    }
    return ret;
}

int32_t DragClient::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->UpdatePreviewStyleWithAnimation(previewStyle, animation);
    if (ret != RET_OK) {
        FI_HILOGE("UpdatePreviewStyleWithAnimation fail");
    }
    return ret;
}

int32_t DragClient::RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->RotateDragWindowSync(rsTransaction);
    if (ret != RET_OK) {
        FI_HILOGE("RotateDragWindowSync fail");
    }
    return ret;
}

int32_t DragClient::GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetDragSummary(summarys, isJsCaller);
    if (ret != RET_OK) {
        FI_HILOGE("GetDragSummary fail");
    }
    return ret;
}

int32_t DragClient::SetDragSwitchState(bool enable, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->SetDragSwitchState(enable, isJsCaller);
    if (ret != RET_OK) {
        FI_HILOGE("SetDragSwitchState fail");
    }
    return ret;
}

int32_t DragClient::SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->SetAppDragSwitchState(enable, pkgName, isJsCaller);
    if (ret != RET_OK) {
        FI_HILOGE("SetAppDragSwitchState fail");
    }
    return ret;
}

int32_t DragClient::GetDragAction(DragAction &dragAction)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetDragAction(dragAction);
    if (ret != RET_OK) {
        FI_HILOGE("GetDragAction fail");
    }
    return ret;
}

int32_t DragClient::GetExtraInfo(std::string &extraInfo)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetExtraInfo(extraInfo);
    if (ret != RET_OK) {
        FI_HILOGE("GetExtraInfo fail");
    }
    return ret;
}

int32_t DragClient::AddPrivilege()
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->AddPrivilege();
    if (ret != RET_OK) {
        FI_HILOGE("AddPrivilege fail");
    }
    return ret;
}

int32_t DragClient::EraseMouseIcon()
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->EraseMouseIcon();
    if (ret != RET_OK) {
        FI_HILOGE("EraseMouseIcon fail");
    }
    return ret;
}

int32_t DragClient::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->SetDragWindowScreenId(displayId, screenId);
    if (ret != RET_OK) {
        FI_HILOGE("SetDragWindowScreenId fail");
    }
    return ret;
}

int32_t DragClient::SetMouseDragMonitorState(bool state)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->SetMouseDragMonitorState(state);
    if (ret != RET_OK) {
        FI_HILOGE("SetMouseDragMonitorState fail");
    }
    return ret;
}

int32_t DragClient::SetDraggableState(bool state)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->SetDraggableState(state);
    if (ret != RET_OK) {
        FI_HILOGE("SetDraggableState fail");
    }
    return ret;
}

int32_t DragClient::GetAppDragSwitchState(bool &state)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetAppDragSwitchState(state);
    if (ret != RET_OK) {
        FI_HILOGE("GetAppDragSwitchState fail");
    }
    return ret;
}

int32_t DragClient::EnableUpperCenterMode(bool enable)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->EnableUpperCenterMode(enable);
    if (ret != RET_OK) {
        FI_HILOGE("EnableUpperCenterMode fail");
    }
    return ret;
}

void DragClient::SetDraggableStateAsync(bool state, int64_t downTime)
{
    CALL_DEBUG_ENTER;
    INTENTION_CLIENT->SetDraggableStateAsync(state, downTime);
}

int32_t DragClient::GetDragBundleInfo(DragBundleInfo &dragBundleInfo)
{
    CALL_DEBUG_ENTER;
    int32_t ret = INTENTION_CLIENT->GetDragBundleInfo(dragBundleInfo);
    if (ret != RET_OK) {
        FI_HILOGE("GetDragBundleInfo fail");
    }
    return ret;
}

int32_t DragClient::OnNotifyResult(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    DragNotifyMsg notifyMsg;
    int32_t result = 0;
    int32_t dragBehavior = -1;
    pkt >> notifyMsg.displayX >> notifyMsg.displayY >> result >> notifyMsg.targetPid >> dragBehavior;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read drag msg failed");
        return RET_ERR;
    }
    if ((result < static_cast<int32_t>(DragResult::DRAG_SUCCESS)) ||
        (result > static_cast<int32_t>(DragResult::DRAG_EXCEPTION))) {
        FI_HILOGE("Invalid result:%{public}d", result);
        return RET_ERR;
    }
    notifyMsg.result = static_cast<DragResult>(result);
    if ((dragBehavior < static_cast<int32_t>(DragBehavior::UNKNOWN)) ||
        (dragBehavior > static_cast<int32_t>(DragBehavior::MOVE))) {
        FI_HILOGE("Invalid dragBehavior:%{public}d", dragBehavior);
        return RET_ERR;
    }
    notifyMsg.dragBehavior = static_cast<DragBehavior>(dragBehavior);
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(startDragListener_, RET_ERR);
    startDragListener_->OnDragEndMessage(notifyMsg);
    return RET_OK;
}

int32_t DragClient::OnStateChangedMessage(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    int32_t state = 0;
    pkt >> state;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read drag msg failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &listener : dragListeners_) {
        listener->OnDragMessage(static_cast<DragState>(state));
    }
    return RET_OK;
}

int32_t DragClient::OnNotifyHideIcon(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(startDragListener_, RET_ERR);
    startDragListener_->OnHideIconMessage();
    return RET_OK;
}

int32_t DragClient::OnDragStyleChangedMessage(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    int32_t style = 0;
    pkt >> style;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read drag msg failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &listener : subscriptListeners_) {
        listener->OnMessage(static_cast<DragCursorStyle>(style));
    }
    return RET_OK;
}

void DragClient::OnConnected()
{
    CALL_INFO_TRACE;
    if (connectedDragListeners_.empty()) {
        FI_HILOGE("The connect drag listener set is empty");
        return;
    }
    for (const auto &listener : connectedDragListeners_) {
        if (AddDraglistener(listener) != RET_OK) {
            FI_HILOGW("AddDraglistener failed");
        }
    }
    connectedDragListeners_.clear();
}

void DragClient::OnDisconnected()
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (dragListeners_.empty()) {
        FI_HILOGE("The drag listener set is empty");
        return;
    }
    connectedDragListeners_ = dragListeners_;
    dragListeners_.clear();
    hasRegistered_ = false;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
