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
namespace {
constexpr int32_t BOOL_INDEX = 0;
constexpr int32_t INT32_INDEX = 1;
constexpr int32_t STRING_INDEX = 2;
constexpr int32_t MAX_ENTITY_INFO_ITEM_SIZE = 50;

bool WriteValueObj(Parcel &parcel, const ValueObj &obj)
{
    int32_t typeIndex = static_cast<int32_t>(obj.index());
    WRITEINT32(parcel, typeIndex, false);
    bool result = std::visit([&parcel](auto &&arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, bool>) {
            WRITEBOOL(parcel, arg, false);
            return true;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            WRITEINT32(parcel, arg, false);
            return true;
        } else if constexpr (std::is_same_v<T, std::string>) {
            WRITESTRING(parcel, arg, false);
            return true;
        }
        return false;
    }, obj);
    return result;
}

bool ReadValueObj(Parcel &parcel, ValueObj &obj)
{
    int32_t typeIndex;
    READINT32(parcel, typeIndex, false);
    switch (typeIndex) {
        case BOOL_INDEX: {
            bool result;
            READBOOL(parcel, result, false);
            obj = result;
            break;
        }
        case INT32_INDEX: {
            int32_t result;
            READINT32(parcel, result, false);
            obj = result;
            break;
        }
        case STRING_INDEX: {
            std::string result;
            READSTRING(parcel, result, false);
            obj = result;
            break;
        }
        default:
            FI_HILOGE("unknown typeIndex:%{public}d", typeIndex);
            return false;
    }
    return true;
}
} // namespace

bool SequenceableCarAwarenessOption::Marshalling(Parcel &parcel) const
{
    WRITEINT32(parcel, static_cast<int32_t>(option_.entityInfo.size()), false);
    for (auto const &[k, v] : option_.entityInfo) {
        WRITESTRING(parcel, k, false);
        WRITEINT32(parcel, static_cast<int32_t>(v.size()), false);
        for (auto const &[ik, iv] : v) {
            WRITESTRING(parcel, ik, false);
            if (!WriteValueObj(parcel, iv)) {
                return false;
            }
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
    READINT32(parcel, size, false);
    CHKCF(size <= MAX_ENTITY_INFO_ITEM_SIZE, "info size over limit");
    for (int32_t i = 0; i < size; i++) {
        std::string key;
        READSTRING(parcel, key, false);
        int32_t innerSize;
        READINT32(parcel, innerSize, false);
        CHKCF(innerSize <= MAX_ENTITY_INFO_ITEM_SIZE, "inner info size over limit");
        for (int32_t j = 0; j < innerSize; j++) {
            std::string innerKey;
            READSTRING(parcel, innerKey, false);
            if (!ReadValueObj(parcel, option_.entityInfo[key][innerKey])) {
                return false;
            }
        }
    }
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS