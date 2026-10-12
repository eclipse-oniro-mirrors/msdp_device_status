/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sequenceable_subscribe_options.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableSubscribeOptions"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
bool SequenceableSubscribeOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(options_.domain))) {
        return false;
    }
    if (!parcel.WriteInt32Vector(options_.patternTypes)) {
        return false;
    }
    return true;
}

bool SequenceableSubscribeOptions::ReadFromParcel(Parcel &parcel)
{
    int32_t domain = 0;
    if (!parcel.ReadInt32(domain)) {
        return false;
    }
    options_.domain = static_cast<PerceptionDomain>(domain);
    if (!parcel.ReadInt32Vector(&options_.patternTypes)) {
        return false;
    }
    return true;
}

SequenceableSubscribeOptions *SequenceableSubscribeOptions::Unmarshalling(Parcel &parcel)
{
    auto *options = new (std::nothrow) SequenceableSubscribeOptions();
    if (options != nullptr && !options->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete options;
        options = nullptr;
    }
    return options;
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
