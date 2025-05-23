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

#include "sequenceable_cooperate_options.h"
 
#include "devicestatus_define.h"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
bool SequenceableCooperateOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(options_.displayX)) {
        FI_HILOGE("displayX WriteInt32 failed");
        return false;
    }
    if (!parcel.WriteInt32(options_.displayY)) {
        FI_HILOGE("displayY WriteInt32 failed");
        return false;
    }
    if (!parcel.WriteInt32(options_.displayId)) {
        FI_HILOGE("displayId WriteInt32 failed");
        return false;
    }
    return true;
}
 
SequenceableCooperateOptions* SequenceableCooperateOptions::Unmarshalling(Parcel &parcel)
{
    SequenceableCooperateOptions *options = new (std::nothrow) SequenceableCooperateOptions();
    CHKPP(options);
    if (!parcel.ReadInt32(options->options_.displayX)) {
        delete options;
        FI_HILOGE("displayX ReadInt32 failed");
        return nullptr;
    }
    if (!parcel.ReadInt32(options->options_.displayY)) {
        delete options;
        FI_HILOGE("displayY ReadInt32 failed");
        return nullptr;
    }
    if (!parcel.ReadInt32(options->options_.displayId)) {
        delete options;
        FI_HILOGE("displayId ReadInt32 failed");
        return nullptr;
    }
    return options;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS