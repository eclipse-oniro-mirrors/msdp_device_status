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
constexpr int32_t MAX_ENTITY_INFO_ITEM_SIZE = 50;

bool SequenceableCarAwarenessOption::Marshalling(Parcel &parcel) const
{
    WRITEINT32_CHECK_RET(parcel, static_cast<int32_t>(option_.entityInfo.size()), false);
    for (auto const &[key, value] : option_.entityInfo) {
        WRITESTRING_CHECK_RET(parcel, key, false);
        WRITESTRING_CHECK_RET(parcel, value, false);
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
        READSTRING_CHECK_RET(parcel, key, false);
        std::string value;
        READSTRING_CHECK_RET(parcel, value, false);
        option_.entityInfo[key] = value;
    }
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
