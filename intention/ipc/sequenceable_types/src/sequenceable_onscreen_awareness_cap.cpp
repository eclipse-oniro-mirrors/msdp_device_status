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

#include "sequenceable_onscreen_awareness_cap.h"

#include "devicestatus_common.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
constexpr int32_t MAX_PARA_LEN = 20;
}
bool SequenceableOnscreenAwarenessCap::Marshalling(Parcel &parcel) const
{
    if (cap_.capList.size() > static_cast<size_t>(MAX_PARA_LEN)) {
        FI_HILOGE("capList size is too long");
        return false;
    }
    WRITEINT32(parcel, static_cast<int32_t>(cap_.capList.size()), false);
    for (size_t i = 0; i < cap_.capList.size(); i++) {
        WRITESTRING(parcel, cap_.capList[i], false);
    }
    WRITESTRING(parcel, cap_.description, false);
    return true;
}

SequenceableOnscreenAwarenessCap* SequenceableOnscreenAwarenessCap::Unmarshalling(Parcel &parcel)
{
    auto cap = new (std::nothrow) SequenceableOnscreenAwarenessCap();
    if (cap != nullptr && !cap->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete cap;
        cap = nullptr;
    }
    return cap;
}

bool SequenceableOnscreenAwarenessCap::ReadFromParcel(Parcel &parcel)
{
    int32_t capListSize = 0;
    READINT32(parcel, capListSize, false);
    std::vector<std::string>().swap(cap_.capList);
    if (capListSize > MAX_PARA_LEN || capListSize < 0) {
        FI_HILOGE("capListSize is too long or illedgal");
        return false;
    }
    for (int32_t i = 0; i < capListSize; i++) {
        std::string cap;
        READSTRING(parcel, cap, false);
        cap_.capList.push_back(cap);
    }
    READSTRING(parcel, cap_.description, false);
    return true;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS