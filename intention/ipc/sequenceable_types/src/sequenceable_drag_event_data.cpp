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

#include "sequenceable_drag_event_data.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableDragEventData"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableDragEventData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint64(dragEventData_.timestampMs)) {
        FI_HILOGE("timestampMs WriteUint64 failed");
        return false;
    }
    if (!parcel.WriteDouble(dragEventData_.coordinateX)) {
        FI_HILOGE("coordinateX WriteDouble failed");
        return false;
    }
    if (!parcel.WriteDouble(dragEventData_.coordinateY)) {
        FI_HILOGE("coordinateY WriteDouble failed");
        return false;
    }
    return true;
}

SequenceableDragEventData* SequenceableDragEventData::Unmarshalling(Parcel &parcel)
{
    SequenceableDragEventData *dragEventData = new (std::nothrow) SequenceableDragEventData();
    if (dragEventData == nullptr) {
        FI_HILOGE("dragEventData is nullptr");
        return nullptr;
    }
    if (!parcel.ReadUint64(dragEventData->dragEventData_.timestampMs)) {
        delete dragEventData;
        FI_HILOGE("TimestampMs ReadUint64 failed");
        return nullptr;
    }
    if (!parcel.ReadDouble(dragEventData->dragEventData_.coordinateX)) {
        delete dragEventData;
        FI_HILOGE("coordinateX ReadDouble failed");
        return nullptr;
    }
    if (!parcel.ReadDouble(dragEventData->dragEventData_.coordinateY)) {
        delete dragEventData;
        FI_HILOGE("coordinateY ReadDouble failed");
        return nullptr;
    }
    return dragEventData;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS