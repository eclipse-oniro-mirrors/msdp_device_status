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

#include "sequenceable_posture_data.h"

#include "devicestatus_common.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
bool SequenceablePostureData::Marshalling(Parcel &parcel) const
{
    WRITEFLOAT(parcel, postureData_.rollRad, false);
    WRITEFLOAT(parcel, postureData_.pitchRad, false);
    WRITEFLOAT(parcel, postureData_.yawRad, false);
    return true;
}

SequenceablePostureData* SequenceablePostureData::Unmarshalling(Parcel &parcel)
{
    auto postureData = new (std::nothrow) SequenceablePostureData();
    if (postureData != nullptr && !postureData->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel is failed");
        delete postureData;
        postureData = nullptr;
    }
    return postureData;
}

bool SequenceablePostureData::ReadFromParcel(Parcel &parcel)
{
    READFLOAT(parcel, postureData_.rollRad, false);
    READFLOAT(parcel, postureData_.pitchRad, false);
    READFLOAT(parcel, postureData_.yawRad, false);
    return true;
}

DevicePostureData SequenceablePostureData::GetPostureData()
{
    return postureData_;
}

void SequenceablePostureData::SetPostureData(const DevicePostureData &postureData)
{
    postureData_ = postureData;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS