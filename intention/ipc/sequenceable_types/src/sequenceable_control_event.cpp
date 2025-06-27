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

#include "sequenceable_control_event.h"

#include "devicestaus_common.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
bool SequenceableControlEvent::Marshalling(Parcel &parcel) const
{
    WRITEINT32(parcel, controlEvent_.windowId, false);
    WRITEINT32(parcel, static_cast<int32_t>(controlEvent_.eventType), false);
    WRITEINT32(parcel, controlEvent_.hookId, false);
    return true;
}

SequenceableControlEvent* SequenceableControlEvent::Unmarshalling(Parcel &parcel)
{
    auto event = new (std::nothrow) SequenceableControlEvent();
    if (event != nullptr && !event->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete event;
        event = nullptr;
    }
    return event;
}

bool SequenceableControlEvent::ReadFromParcel(Parcel &parcel)
{
    int32_t eventType = 0;
    READINT32(parcel, controlEvent_.windowId, false);
    READINT32(parcel, eventType, false);
    READINT32(parcel, controlEvent_.hookId, false);
    if (eventType < 0 || eventType > static_cast<int32_t>(EventType::SCROLL_TO_HOOK)) {
        return false;
    }
    controlEvent_.eventType = static_cast<EventType>(eventType);
    return true;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS