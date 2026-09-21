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

#include "sequenceable_car_awareness_option.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr int32_t MAX_ENTITY_INFO_ITEM_SIZE = 50;

bool SequenceableCarAwarenessOption::Marshalling(Parcel &parcel) const
{
    if (!WriteInt32(parcel, static_cast<int32_t>(option_.entityInfo.size()))) {
        return false;
    }
    for (auto const &[key, value] : option_.entityInfo) {
        if (!WriteString(parcel, key)) {
            return false;
        }
        if (!WriteString(parcel, value)) {
            return false;
        }
    }
    return true;
}

SequenceableCarAwarenessOption* SequenceableCarAwarenessOption::Unmarshalling(Parcel &parcel)
{
    auto option = new (std::nothrow) SequenceableCarAwarenessOption();
    if (option != nullptr && !option->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete option;
        option = nullptr;
    }
    return option;
}

bool SequenceableCarAwarenessOption::ReadFromParcel(Parcel &parcel)
{
    int32_t size;
    if (!ReadInt32(parcel, size)) {
        return false;
    }
    CHKCF(size >= 0 && size <= MAX_ENTITY_INFO_ITEM_SIZE, "info size over limit");
    for (int32_t i = 0; i < size; i++) {
        std::string key;
        if (!ReadString(parcel, key)) {
            return false;
        }
        std::string value;
        if (!ReadString(parcel, value)) {
            return false;
        }
        option_.entityInfo[key] = value;
    }
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS