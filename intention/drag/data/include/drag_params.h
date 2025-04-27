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

#ifndef DRAG_PARAMS_H
#define DRAG_PARAMS_H

#include <memory>

#include "transaction/rs_transaction.h"

#include "default_params.h"
#include "drag_data.h"
#include "intention_identity.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum DragRequestID : uint32_t {
    UNKNOWN_DRAG_ACTION,
    ADD_DRAG_LISTENER,
    REMOVE_DRAG_LISTENER,
    ADD_SUBSCRIPT_LISTENER,
    REMOVE_SUBSCRIPT_LISTENER,
    SET_DRAG_WINDOW_VISIBLE,
    UPDATE_DRAG_STYLE,
    UPDATE_SHADOW_PIC,
    GET_DRAG_TARGET_PID,
    GET_UDKEY,
    GET_SHADOW_OFFSET,
    GET_DRAG_DATA,
    UPDATE_PREVIEW_STYLE,
    UPDATE_PREVIEW_STYLE_WITH_ANIMATION,
    ROTATE_DRAG_WINDOW_SYNC,
    GET_DRAG_SUMMARY,
    SET_DRAG_SWITCH_STATE,
    SET_APP_DRAG_SWITCH_STATE,
    GET_DRAG_STATE,
    ADD_PRIVILEGE,
    ENTER_TEXT_EDITOR_AREA,
    SET_MOUSE_DRAG_MONITOR_STATE,
    GET_DRAG_ACTION,
    GET_EXTRA_INFO,
    ERASE_MOUSE_ICON,
    SET_DRAG_WINDOW_SCREEN_ID,
    ADD_SELECTED_PIXELMAP,
    SET_DRAGGABLE_STATE,
    SET_DRAGABLE_STATE_ASYNC,
    GET_UNIVERSAL_DRAG_APP_STATE,
};

struct StartDragParam final : public ParamBase {
    explicit StartDragParam(DragData &dragData);
    explicit StartDragParam(const DragData &dragData);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    // For efficiency, we want to avoid copying 'DragData' whenever possible.
    // Considering the 'Start drag' scenario, we use 'StartDragParam' simply
    // as wrapper of 'DragData' and serialize 'DragData' in the right same
    // call. We do not dereference 'DragData' or keep a reference to it for
    // later use. In this case, we can safely keep a pointer to the input 'DragData'.
    DragData *dragDataPtr_ { nullptr };
    const DragData *cDragDataPtr_ { nullptr };
};

struct StopDragParam final : public ParamBase {
    StopDragParam() = default;
    explicit StopDragParam(const DragDropResult &dropResult);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    DragDropResult dropResult_ {};
};

struct SetDragWindowVisibleParam final : public ParamBase {
    SetDragWindowVisibleParam() = default;
    SetDragWindowVisibleParam(bool visible, bool isForce, const std::shared_ptr<Rosen::RSTransaction>& rsTransaction);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool visible_ { false };
    bool isForce_ { false };
    std::shared_ptr<Rosen::RSTransaction> rsTransaction_ { nullptr };
};

struct UpdateDragStyleParam final : public ParamBase {
    UpdateDragStyleParam() = default;
    explicit UpdateDragStyleParam(DragCursorStyle style, int32_t eventId);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    DragCursorStyle cursorStyle_ { DragCursorStyle::DEFAULT };
    int32_t eventId_ { -1 };
};

struct UpdateShadowPicParam final : public ParamBase {
    UpdateShadowPicParam() = default;
    explicit UpdateShadowPicParam(const ShadowInfo &shadowInfo);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    ShadowInfo shadowInfo_ {};
};

struct GetDragTargetPidReply : public ParamBase {
    GetDragTargetPidReply() = default;
    explicit GetDragTargetPidReply(int32_t pid);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    int32_t targetPid_ { -1 };
};

struct GetUdKeyReply final : public ParamBase {
    GetUdKeyReply() = default;
    explicit GetUdKeyReply(std::string &&udKey);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string udKey_;
};

struct GetShadowOffsetReply final : public ParamBase {
    GetShadowOffsetReply() = default;
    explicit GetShadowOffsetReply(const ShadowOffset &shadowOffset);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    ShadowOffset shadowOffset_ {};
};

using GetDragDataReply = StartDragParam;

struct UpdatePreviewStyleParam final : public ParamBase {
    UpdatePreviewStyleParam() = default;
    explicit UpdatePreviewStyleParam(const PreviewStyle &previewStyle);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    PreviewStyle previewStyle_;
};

struct UpdatePreviewAnimationParam final : public ParamBase {
    UpdatePreviewAnimationParam() = default;
    UpdatePreviewAnimationParam(const PreviewStyle &previewStyle, const PreviewAnimation &animation);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    PreviewStyle previewStyle_ {};
    PreviewAnimation previewAnimation_ {};
};

struct RotateDragWindowSyncParam final : public ParamBase {
    RotateDragWindowSyncParam() = default;
    explicit RotateDragWindowSyncParam(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::shared_ptr<Rosen::RSTransaction> rsTransaction_ { nullptr };
};

struct SetDragWindowScreenIdParam final : public ParamBase {
    SetDragWindowScreenIdParam() = default;
    SetDragWindowScreenIdParam(uint64_t displayId, uint64_t screenId);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    uint64_t displayId_ { 0 };
    uint64_t screenId_ { 0 };
};

struct AddDraglistenerParam final : public ParamBase {
    AddDraglistenerParam() = default;
    AddDraglistenerParam(bool isJsCaller);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool isJsCaller_ { false };
};

struct RemoveDraglistenerParam final : public ParamBase {
    RemoveDraglistenerParam() = default;
    RemoveDraglistenerParam(bool isJsCaller);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool isJsCaller_ { false };
};

struct GetDragSummaryParam final : public ParamBase {
    GetDragSummaryParam() = default;
    GetDragSummaryParam(bool isJsCaller);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool isJsCaller_ { false };
};

struct GetDragSummaryReply final : public ParamBase {
    GetDragSummaryReply() = default;
    explicit GetDragSummaryReply(std::map<std::string, int64_t> &&summary);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::map<std::string, int64_t> summary_;
};

struct SetDragSwitchStateParam final : public ParamBase {
    SetDragSwitchStateParam() = default;
    SetDragSwitchStateParam(bool enable, bool isJsCaller);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool enable_ { false };
    bool isJsCaller_ { false };
};

struct SetAppDragSwitchStateParam final : public ParamBase {
    SetAppDragSwitchStateParam() = default;
    SetAppDragSwitchStateParam(bool enable, const std::string &pkgName, bool isJsCaller);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool enable_ { false };
    std::string pkgName_;
    bool isJsCaller_ { false };
};

struct GetDragStateReply final : public ParamBase {
    GetDragStateReply() = default;
    explicit GetDragStateReply(DragState dragState);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    DragState dragState_ { DragState::ERROR };
};

using EnterTextEditorAreaParam = BooleanReply;
using SetMouseDragMonitorStateParam = BooleanReply;
struct GetDragActionReply final : public ParamBase {
    GetDragActionReply() = default;
    explicit GetDragActionReply(DragAction dragAction);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    DragAction dragAction_ { DragAction::INVALID };
};

struct GetExtraInfoReply final : public ParamBase {
    GetExtraInfoReply() = default;
    explicit GetExtraInfoReply(std::string &&extraInfo);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string extraInfo_;
};

struct AddSelectedPixelMapParam final : public ParamBase {
    AddSelectedPixelMapParam() = default;
    explicit AddSelectedPixelMapParam(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap_ { nullptr };
};

struct SetDraggableStateParam final : public ParamBase {
    SetDraggableStateParam() = default;
    SetDraggableStateParam(bool draggable);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool state_ { false };
};

struct GetUniversalDragAppStateReply final : public ParamBase {
    GetUniversalDragAppStateReply() = default;
    explicit GetUniversalDragAppStateReply(bool state);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool state_ { false };
};

struct SetDraggableStateAsyncParam final : public ParamBase {
    SetDraggableStateAsyncParam() = default;
    SetDraggableStateAsyncParam(bool state, int64_t downTime);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    bool state_ { false };
    int64_t downTime_ { -1 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_PARAMS_H
