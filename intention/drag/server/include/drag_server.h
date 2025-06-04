/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DRAG_SERVER_H
#define DRAG_SERVER_H

#include "nocopyable.h"

#include "accesstoken_kit.h"
#include "i_context.h"
#include "i_plugin.h"
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
#include "universal_drag_wrapper.h"
#endif // OHOS_BUILD_UNIVERSAL_DRAG

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragServer final {
public:
    DragServer(IContext *env);
    ~DragServer() = default;
    DISALLOW_COPY_AND_MOVE(DragServer);

    int32_t StartDrag(CallingContext &context, const DragData &dragData);
    int32_t StopDrag(CallingContext &context, const DragDropResult &dropResult);
    int32_t EnableInternalDropAnimation(CallingContext &context, const std::string &animationInfo);
    int32_t AddDraglistener(CallingContext &context, bool isJsCaller);
    int32_t RemoveDraglistener(CallingContext &context, bool isJsCaller);
    int32_t UpdateDragStyle(CallingContext &context, DragCursorStyle style, int32_t eventId);
    int32_t UpdateShadowPic(const ShadowInfo &shadowInfo);
    int32_t AddSubscriptListener(CallingContext &context);
    int32_t RemoveSubscriptListener(CallingContext &context);
    int32_t SetDragWindowVisible(bool visible, bool isForce,
        const std::shared_ptr<Rosen::RSTransaction>& rsTransaction);
    int32_t GetDragTargetPid(CallingContext &context, int32_t &targetPid);
    int32_t GetUdKey(std::string &udKey);
    int32_t GetShadowOffset(ShadowOffset &shadowOffset);
    int32_t GetDragData(CallingContext &context, DragData &dragData);
    int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle);
    int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation);
    int32_t RotateDragWindowSync(CallingContext &context, const std::shared_ptr<Rosen::RSTransaction>& rsTransaction);
    int32_t SetDragWindowScreenId(CallingContext &context, uint64_t displayId, uint64_t screenId);
    int32_t GetDragSummary(CallingContext &context, std::map<std::string, int64_t> &summarys, bool isJsCaller);
    int32_t SetDragSwitchState(CallingContext &context, bool enable, bool isJsCaller);
    int32_t SetAppDragSwitchState(CallingContext &context, bool enable, const std::string &pkgName, bool isJsCaller);
    int32_t GetDragState(DragState &dragState);
    int32_t EnableUpperCenterMode(bool enable);
    int32_t GetDragAction(DragAction &dragAction);
    int32_t GetExtraInfo(std::string &extraInfo);
    int32_t AddPrivilege(CallingContext &context);
    int32_t EraseMouseIcon(CallingContext &context);
    int32_t SetMouseDragMonitorState(bool state);
    int32_t SetDraggableState(bool state);
    int32_t GetAppDragSwitchState(bool &state);
    int32_t SetDraggableStateAsync(bool state, int64_t downTime);
    int32_t GetDragBundleInfo(DragBundleInfo &dragBundleInfo);

private:
    std::string GetPackageName(Security::AccessToken::AccessTokenID tokenId);
    bool IsSystemServiceCalling(CallingContext &context);
    bool IsSystemHAPCalling(CallingContext &context);
private:
    IContext *env_ { nullptr };
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    UniversalDragWrapper universalDragWrapper_;
#endif // OHOS_BUILD_UNIVERSAL_DRAG
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_SERVER_H