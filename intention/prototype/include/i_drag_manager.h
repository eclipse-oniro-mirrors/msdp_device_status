/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef I_DRAG_MANAGER_H
#define I_DRAG_MANAGER_H

#include <cstdint>
#include <functional>

#include <display_manager.h>
#include <input_manager.h>
#include "transaction/rs_transaction.h"

#include "drag_data.h"
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "stream_session.h"
#else
#include "virtual_rs_window.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IDragManager {
public:
    IDragManager() = default;
    virtual ~IDragManager() = default;

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    virtual void Dump(int32_t fd) const = 0;
    virtual int32_t AddListener(int32_t pid) = 0;
    virtual int32_t RemoveListener(int32_t pid) = 0;
    virtual int32_t AddSubscriptListener(int32_t pid) = 0;
    virtual int32_t RemoveSubscriptListener(int32_t pid) = 0;
    virtual int32_t StartDrag(
        const DragData &dragData, int32_t pid, const std::string &peerNetId = "", bool isLongPressDrag = false,
        const std::string &appCaller = "") = 0;
#else
    virtual int32_t StartDrag(const DragData &dragData) = 0;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    virtual int32_t StopDrag(const DragDropResult &dropResult, const std::string &packageName = "",
        int32_t pid = -1, bool isStopCooperate = false,  const std::string &appCallee = "") = 0;
    virtual int32_t GetDragData(DragData &dragData) = 0;
    virtual int32_t GetDragTargetPid() const = 0;
    virtual int32_t GetUdKey(std::string &udKey) const = 0;
    virtual int32_t OnGetShadowOffset(ShadowOffset &shadowOffset) = 0;
    virtual DragState GetDragState() const = 0;
    virtual int32_t GetDragState(DragState &dragState) = 0;
    virtual DragCursorStyle GetDragStyle() const = 0;
    virtual int32_t GetExtraInfo(std::string &extraInfo) const = 0;
    virtual void SetDragState(DragState state) = 0;
    virtual void SetDragOriginDpi(float dragOriginDpi) = 0;
    virtual DragResult GetDragResult() const = 0;
    virtual std::string GetAppCallee() const = 0;
    virtual int32_t GetDragSummary(std::map<std::string, int64_t> &summarys) = 0;
    virtual int32_t GetDragAction(DragAction &dragAction) const = 0;
    virtual int32_t OnSetDragWindowVisible(
        bool visible, bool isForce = false, bool isZoomInAndAlphaChanged = false) = 0;
    virtual OHOS::MMI::ExtraData GetExtraData(bool appended) const = 0;
    virtual bool GetControlCollaborationVisible() const = 0;
    virtual void SetControlCollaborationVisible(bool visible) = 0;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    virtual void RegisterStateChange(std::function<void(DragState)> callback) = 0;
    virtual void UnregisterStateChange() = 0;
    virtual void RegisterNotifyPullUp(std::function<void(bool)> callback) = 0;
    virtual void UnregisterNotifyPullUp() = 0;
    virtual void RegisterCrossDrag(std::function<void(bool)> callback) = 0;
    virtual void UnregisterCrossDrag() = 0;
    virtual void NotifyCrossDrag(bool isButtonDown) = 0;
    virtual bool IsCrossDragging() = 0;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    virtual void SetPointerEventFilterTime(int64_t filterTime) = 0;
    virtual void MoveTo(int32_t x, int32_t y, bool isMultiSelectedAnimation = true) = 0;
    virtual void SetMultiSelectedAnimationFlag(bool needMultiSelectedAnimation) = 0;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    virtual int32_t UpdateDragStyle(
        DragCursorStyle style, int32_t targetPid, int32_t targetTid, int32_t eventId = -1) = 0;
#else
    virtual int32_t UpdateDragStyle(DragCursorStyle style) = 0;
    virtual void SetDragWindow(std::shared_ptr<OHOS::Rosen::Window> window) = 0;
    virtual void AddDragDestroy(std::function<void()> cb) = 0;
    virtual void SetSVGFilePath(const std::string &filePath) = 0;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    virtual int32_t UpdateShadowPic(const ShadowInfo &shadowInfo) = 0;
    virtual int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle) = 0;
    virtual int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
        const PreviewAnimation &animation) = 0;
    virtual int32_t RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction = nullptr) = 0;
    virtual void GetAllowDragState(bool &isAllowDrag) = 0;
    virtual int32_t RotateDragWindow(Rosen::Rotation rotation) = 0;
    virtual int32_t ScreenRotate(Rosen::Rotation rotation, Rosen::Rotation lastRotation) = 0;
    virtual int32_t EnterTextEditorArea(bool enable) = 0;
    virtual int32_t AddPrivilege(int32_t tokenId) = 0;
    virtual int32_t EraseMouseIcon() = 0;
    virtual void SetDragWindowScreenId(uint64_t displayId, uint64_t screenId) = 0;
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    virtual int32_t AddSelectedPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap) = 0;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    virtual int32_t SetMouseDragMonitorState(bool state) = 0;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DRAG_MANAGER_H