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

#include "sequenceable_state_mgmt_info.h"

#include "devicestatus_common.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
bool SequenceableStateMgmtInfo::Marshalling(Parcel &parcel) const
{
    WRITESTRING(parcel, stateMgmtInfo_.componentName, false);
    WRITESTRING(parcel, stateMgmtInfo_.propertyName, false);
    WRITESTRING(parcel, stateMgmtInfo_.jsonPath, false);
    WRITEBOOL(parcel, stateMgmtInfo_.onlyVisible, false);
    return true;
}

SequenceableStateMgmtInfo* SequenceableStateMgmtInfo::Unmarshalling(Parcel &parcel)
{
    auto info = new (std::nothrow) SequenceableStateMgmtInfo();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SequenceableStateMgmtInfo::ReadFromParcel(Parcel &parcel)
{
    READSTRING(parcel, stateMgmtInfo_.componentName, false);
    READSTRING(parcel, stateMgmtInfo_.propertyName, false);
    READSTRING(parcel, stateMgmtInfo_.jsonPath, false);
    READBOOL(parcel, stateMgmtInfo_.onlyVisible, false);
    return true;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
