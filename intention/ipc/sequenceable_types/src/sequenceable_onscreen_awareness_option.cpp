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

#include "sequenceable_onscreen_awareness_option.h"

#include "devicestatus_common.h"
#include "sequenceable_util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
bool SequenceableOnscreenAwarenessOption::Marshalling(Parcel &parcel) const
{
    return SequenceableUtil::Marshalling(parcel, option_.entityInfo);
}

SequenceableOnscreenAwarenessOption* SequenceableOnscreenAwarenessOption::Unmarshalling(Parcel &parcel)
{
    auto option = new (std::nothrow) SequenceableOnscreenAwarenessOption();
    if (option != nullptr && !option->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete option;
        option = nullptr;
    }
    return option;
}

bool SequenceableOnscreenAwarenessOption::ReadFromParcel(Parcel &parcel)
{
    return SequenceableUtil::Unmarshalling(parcel, option_.entityInfo);
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS