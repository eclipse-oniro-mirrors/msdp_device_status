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

#ifndef INTENTION_DRAG_CLIENT_H
#define INTENTION_DRAG_CLIENT_H

#include "nocopyable.h"

#include <set>

#include "i_hotarea_listener.h"
#include "i_drag_listener.h"
#include "i_subscript_listener.h"
#include "i_start_drag_listener.h"
#include "socket_client.h"
#include "transaction/rs_transaction.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragClient final {
public:
    DragClient() = default;
    ~DragClient() = default;
    DISALLOW_COPY_AND_MOVE(DragClient);
    int32_t StartDrag(const DragData &dragData, std::shared_ptr<IStartDragListener> listener);
    int32_t StopDrag(const DragDropResult &dropResult);
    int32_t AddDraglistener(DragListenerPtr listener, bool isJsCaller = false);
    int32_t RemoveDraglistener(DragListenerPtr listener, bool isJsCaller = false);
    int32_t AddSubscriptListener(SubscriptListenerPtr listener);
    int32_t RemoveSubscriptListener(SubscriptListenerPtr listener);
    int32_t SetDragWindowVisible(bool visible, bool isForce,
        const std::shared_ptr<Rosen::RSTransaction>& rsTransaction = nullptr);
    int32_t UpdateDragStyle(DragCursorStyle style, int32_t eventId = -1);
    int32_t UpdateShadowPic(const ShadowInfo &shadowInfo);
    int32_t GetDragTargetPid();
    int32_t GetUdKey(std::string &udKey);
    int32_t GetShadowOffset(ShadowOffset &shadowOffset);
    int32_t GetDragData(DragData &dragData);
    int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle);
    int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation);
    int32_t RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction = nullptr);
    int32_t SetDragWindowScreenId(uint64_t displayId, uint64_t screenId);
    int32_t GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller = false);
    int32_t SetDragSwitchState(bool enable, bool isJsCaller = false);
    int32_t SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller = false);
    int32_t GetDragState(DragState &dragState);
    int32_t EnableUpperCenterMode(bool enable);
    int32_t GetDragAction(DragAction &dragAction);
    int32_t GetExtraInfo(std::string &extraInfo);
    int32_t AddPrivilege();
    int32_t EraseMouseIcon();
    int32_t SetMouseDragMonitorState(bool state);
    int32_t OnNotifyResult(const StreamClient &client, NetPacket &pkt);
    int32_t OnNotifyHideIcon(const StreamClient &client, NetPacket &pkt);
    int32_t OnStateChangedMessage(const StreamClient &client, NetPacket &pkt);
    int32_t OnDragStyleChangedMessage(const StreamClient &client, NetPacket &pkt);
    int32_t GetDragBundleInfo(DragBundleInfo &dragBundleInfo);
    int32_t SetDraggableState(bool state);
    int32_t GetAppDragSwitchState(bool &state);
    void SetDraggableStateAsync(bool state, int64_t downTime);

    void OnConnected();
    void OnDisconnected();

private:
    mutable std::mutex mtx_;
    std::shared_ptr<IStartDragListener> startDragListener_ { nullptr };
    bool hasRegistered_ { false };
    bool hasSubscriptRegistered_ { false };
    std::set<DragListenerPtr> dragListeners_;
    std::set<DragListenerPtr> connectedDragListeners_;
    std::set<SubscriptListenerPtr> subscriptListeners_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_DRAG_CLIENT_H
