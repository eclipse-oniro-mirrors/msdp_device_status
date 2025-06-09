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

#include "sequenceable_drag_data.h"

#include "devicestatus_define.h"
#include "drag_data_packer.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableDragData"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableDragData::Marshalling(Parcel &parcel) const
{
    if (DragDataPacker::Marshalling(dragData_, parcel) != RET_OK) {
        return false;
    }

    if (DragDataPacker::MarshallingSummarys2(dragData_, parcel) != RET_OK) {
        FI_HILOGE("Marshalling summarys2 failed");
    }
    return true;
}

SequenceableDragData* SequenceableDragData::Unmarshalling(Parcel &parcel)
{
    SequenceableDragData *sequenceDragData = new (std::nothrow) SequenceableDragData();
    CHKPP(sequenceDragData);
    if (DragDataPacker::UnMarshalling(parcel, sequenceDragData->dragData_) != RET_OK) {
        delete sequenceDragData;
        return nullptr;
    }

    if (DragDataPacker::UnMarshallingSummarys2(parcel, sequenceDragData->dragData_) != RET_OK) {
        FI_HILOGE("UnMarshalling summarys2 failed");
    }
    return sequenceDragData;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS