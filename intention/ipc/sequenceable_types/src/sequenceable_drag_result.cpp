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

#include "sequenceable_drag_result.h"

#include "devicestatus_define.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableDragResult::Marshalling(Parcel &parcel) const
{
    return (
        parcel.WriteInt32(static_cast<int32_t>(dragDropResult_.result)) &&
        parcel.WriteInt32(dragDropResult_.mainWindow) &&
        parcel.WriteBool(dragDropResult_.hasCustomAnimation) &&
        parcel.WriteInt32(static_cast<int32_t>(dragDropResult_.dragBehavior))
    );
}

SequenceableDragResult* SequenceableDragResult::Unmarshalling(Parcel &parcel)
{
    SequenceableDragResult *sequenceDragResult = new (std::nothrow) SequenceableDragResult();
    CHKPP(sequenceDragResult);
    int32_t result { -1 };
    if (!parcel.ReadInt32(result) ||
        (result < static_cast<int32_t>(DragResult::DRAG_SUCCESS)) ||
        (result > static_cast<int32_t>(DragResult::DRAG_EXCEPTION))) {
        delete sequenceDragResult;
        return nullptr;
    }
    sequenceDragResult->dragDropResult_.result = static_cast<DragResult>(result);
    if (!parcel.ReadInt32(sequenceDragResult->dragDropResult_.mainWindow) ||
        !parcel.ReadBool(sequenceDragResult->dragDropResult_.hasCustomAnimation)) {
        delete sequenceDragResult;
        return nullptr;
    }
    int32_t dragBehavior { -1 };
    if (!parcel.ReadInt32(dragBehavior) ||
        (dragBehavior < static_cast<int32_t>(DragBehavior::UNKNOWN)) ||
        (dragBehavior > static_cast<int32_t>(DragBehavior::MOVE))) {
        delete sequenceDragResult;
        return nullptr;
    }
    sequenceDragResult->dragDropResult_.dragBehavior = static_cast<DragBehavior>(dragBehavior);
    return sequenceDragResult;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS