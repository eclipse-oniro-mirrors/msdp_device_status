/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "sequenceable_car_awareness_event_array.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableCarAwarenessEventArray::Marshalling(Parcel &parcel) const
{
    if (!WriteInt32(parcel, static_cast<int32_t>(events_.size()))) {
        return false;
    }
    for (const auto &event : events_) {
        if (!WriteInt32(parcel, event.type)) {
            return false;
        }
        if (!WriteString(parcel, event.eventData)) {
            return false;
        }
    }
    return true;
}

SequenceableCarAwarenessEventArray* SequenceableCarAwarenessEventArray::Unmarshalling(Parcel &parcel)
{
    auto events = new (std::nothrow) SequenceableCarAwarenessEventArray();
    if (events != nullptr && !events->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete events;
        events = nullptr;
    }
    return events;
}

bool SequenceableCarAwarenessEventArray::ReadFromParcel(Parcel &parcel)
{
    int32_t size = 0;
    if (!ReadInt32(parcel, size)) {
        return false;
    }
    constexpr int32_t MAX_EVENT_ARRAY_SIZE = 1000;
    if (size < 0 || size > MAX_EVENT_ARRAY_SIZE) {
        FI_HILOGE("size:%{public}d is invalid", size);
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        CarAwarenessEvent event;
        if (!ReadInt32(parcel, event.type)) {
            return false;
        }
        if (!ReadString(parcel, event.eventData)) {
            return false;
        }
        events_.push_back(event);
    }
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS