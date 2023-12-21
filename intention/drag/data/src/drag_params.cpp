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

#include "drag_params.h"

#include "devicestatus_define.h"
#include "drag_data_packer.h"
#include "preview_style_packer.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

StartDragParam::StartDragParam(DragData &dragData)
{
    dragDataPtr_ = &dragData;
}

StartDragParam::StartDragParam(const DragData &dragData)
{
    cDragDataPtr_ = &dragData;
}

bool StartDragParam::Marshalling(MessageParcel &parcel) const
{
    return (
        (cDragDataPtr_ != nullptr) &&
        (DragDataPacker::Marshalling(*cDragDataPtr_, parcel) == RET_OK)
    );
}

bool StartDragParam::Unmarshalling(MessageParcel &parcel)
{
    return (
        (dragDataPtr_ != nullptr) &&
        (DragDataPacker::UnMarshalling(parcel, *dragDataPtr_) == RET_OK)
    );
}

StopDragParam::StopDragParam(const DragDropResult &dropResult)
    : dropResult_(dropResult)
{}

bool StopDragParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(static_cast<int32_t>(dropResult_.result)) &&
        parcel.WriteInt32(dropResult_.windowId) &&
        parcel.WriteBool(dropResult_.hasCustomAnimation)
    );
}

bool StopDragParam::Unmarshalling(MessageParcel &parcel)
{
    int32_t result { -1 };
    if (!parcel.ReadInt32(result) ||
        (result < static_cast<int32_t>(DragResult::DRAG_SUCCESS)) ||
        (result > static_cast<int32_t>(DragResult::DRAG_EXCEPTION))) {
        return false;
    }
    dropResult_.result = static_cast<DragResult>(result);
    return (
        parcel.ReadInt32(dropResult_.windowId) &&
        parcel.ReadBool(dropResult_.hasCustomAnimation)
    );
}

SetDragWindowVisibleParam::SetDragWindowVisibleParam(bool visible)
    : visible_(visible)
{}

bool SetDragWindowVisibleParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteBool(visible_);
}

bool SetDragWindowVisibleParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadBool(visible_);
}

UpdateDragStyleParam::UpdateDragStyleParam(DragCursorStyle style)
    : cursorStyle_(style)
{}

bool UpdateDragStyleParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(static_cast<int32_t>(cursorStyle_));
}

bool UpdateDragStyleParam::Unmarshalling(MessageParcel &parcel)
{
    int32_t style { -1 };
    if (!parcel.ReadInt32(style) ||
        (style < static_cast<int32_t>(DragCursorStyle::DEFAULT)) ||
        (style > static_cast<int32_t>(DragCursorStyle::MOVE))) {
        return false;
    }
    cursorStyle_ = static_cast<DragCursorStyle>(style);
    return true;
}

UpdateShadowPicParam::UpdateShadowPicParam(const ShadowInfo &shadowInfo)
    : shadowInfo_(shadowInfo)
{}

bool UpdateShadowPicParam::Marshalling(MessageParcel &parcel) const
{
    return (
        (shadowInfo_.pixelMap != nullptr) &&
        shadowInfo_.pixelMap->Marshalling(parcel) &&
        parcel.WriteInt32(shadowInfo_.x) &&
        parcel.WriteInt32(shadowInfo_.y)
    );
}

bool UpdateShadowPicParam::Unmarshalling(MessageParcel &parcel)
{
    shadowInfo_.pixelMap = std::shared_ptr<Media::PixelMap>(Media::PixelMap::Unmarshalling(parcel));
    return (
        (shadowInfo_.pixelMap != nullptr) &&
        parcel.ReadInt32(shadowInfo_.x) &&
        parcel.ReadInt32(shadowInfo_.y)
    );
}

GetDragTargetPidReply::GetDragTargetPidReply(int32_t pid)
    : targetPid_(pid)
{}

bool GetDragTargetPidReply::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(targetPid_);
}

bool GetDragTargetPidReply::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadInt32(targetPid_);
}

GetUdKeyReply::GetUdKeyReply(std::string &&udKey)
    : udKey_(std::move(udKey))
{}

bool GetUdKeyReply::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteString(udKey_);
}

bool GetUdKeyReply::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadString(udKey_);
}

GetShadowOffsetReply::GetShadowOffsetReply(int32_t offsetX, int32_t offsetY, int32_t width, int32_t height)
    : offsetX_(offsetX), offsetY_(offsetY), width_(width), height_(height)
{}

bool GetShadowOffsetReply::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(offsetX_) &&
        parcel.WriteInt32(offsetY_) &&
        parcel.WriteInt32(width_) &&
        parcel.WriteInt32(height_)
    );
}

bool GetShadowOffsetReply::Unmarshalling(MessageParcel &parcel)
{
    return (
        parcel.ReadInt32(offsetX_) &&
        parcel.ReadInt32(offsetY_) &&
        parcel.ReadInt32(width_) &&
        parcel.ReadInt32(height_)
    );
}

UpdatePreviewStyleParam::UpdatePreviewStyleParam(const PreviewStyle &previewStyle)
    : previewStyle_(previewStyle)
{}

bool UpdatePreviewStyleParam::Marshalling(MessageParcel &parcel) const
{
    return (PreviewStylePacker::Marshalling(previewStyle_, parcel) == RET_OK);
}

bool UpdatePreviewStyleParam::Unmarshalling(MessageParcel &parcel)
{
    return (PreviewStylePacker::UnMarshalling(parcel, previewStyle_) == RET_OK);
}

UpdatePreviewAnimationParam::UpdatePreviewAnimationParam(
    const PreviewStyle &previewStyle, const PreviewAnimation &animation)
    : previewStyle_(previewStyle), previewAnimation_(animation)
{}

bool UpdatePreviewAnimationParam::Marshalling(MessageParcel &parcel) const
{
    return (
        (PreviewStylePacker::Marshalling(previewStyle_, parcel) == RET_OK) &&
        (PreviewAnimationPacker::Marshalling(previewAnimation_, parcel) == RET_OK)
    );
}

bool UpdatePreviewAnimationParam::Unmarshalling(MessageParcel &parcel)
{
    return (
        (PreviewStylePacker::UnMarshalling(parcel, previewStyle_) == RET_OK) &&
        (PreviewAnimationPacker::UnMarshalling(parcel, previewAnimation_) == RET_OK)
    );
}

GetDragSummaryReply::GetDragSummaryReply(std::map<std::string, int64_t> &&summaries)
    : summaries_(std::move(summaries))
{}

bool GetDragSummaryReply::Marshalling(MessageParcel &parcel) const
{
    return (SummaryPacker::Marshalling(summaries_, parcel) == RET_OK);
}

bool GetDragSummaryReply::Unmarshalling(MessageParcel &parcel)
{
    return (SummaryPacker::UnMarshalling(parcel, summaries_) == RET_OK);
}

GetDragStateReply::GetDragStateReply(DragState dragState)
    : dragState_(dragState)
{}

bool GetDragStateReply::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(static_cast<int32_t>(dragState_));
}

bool GetDragStateReply::Unmarshalling(MessageParcel &parcel)
{
    int32_t dragState { -1 };
    if (!parcel.ReadInt32(dragState) ||
        (dragState < static_cast<int32_t>(DragState::ERROR)) ||
        (dragState > static_cast<int32_t>(DragState::MOTION_DRAGGING))) {
        return false;
    }
    dragState_ = static_cast<DragState>(dragState);
    return true;
}

EnterTextEditorAreaParam::EnterTextEditorAreaParam(bool enable)
    : enable_(enable)
{}

bool EnterTextEditorAreaParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteBool(enable_);
}

bool EnterTextEditorAreaParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadBool(enable_);
}

GetDragActionReply::GetDragActionReply(DragAction dragAction)
    : dragAction_(dragAction)
{}

bool GetDragActionReply::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(static_cast<int32_t>(dragAction_));
}

bool GetDragActionReply::Unmarshalling(MessageParcel &parcel)
{
    int32_t dragAction { -1 };
    if (!parcel.ReadInt32(dragAction) ||
        (dragAction < static_cast<int32_t>(DragAction::INVALID)) ||
        (dragAction > static_cast<int32_t>(DragAction::COPY))) {
        return false;
    }
    dragAction_ = static_cast<DragAction>(dragAction);
    return true;
}

GetExtraInfoReply::GetExtraInfoReply(std::string &&extraInfo)
    : extraInfo_(std::move(extraInfo))
{}

bool GetExtraInfoReply::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteString(extraInfo_);
}

bool GetExtraInfoReply::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadString(extraInfo_);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS