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

#include "sequenceable_onscreen_awareness_info.h"

#include "devicestatus_common.h"
#include "sequenceable_util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
// constexpr int32_t MAX_PARA_LEN = 20;
}
bool SequenceableOnscreenAwarenessInfo::Marshalling(Parcel &parcel) const
{
    WRITEINT32(parcel, info_.resultCode, false);
    WRITESTRING(parcel, info_.timestamp, false);
    WRITESTRING(parcel, info_.bundleName, false);
    WRITESTRING(parcel, info_.appID, false);
    WRITEINT32(parcel, info_.appIndex, false);
    WRITESTRING(parcel, info_.pageId, false);
    WRITESTRING(parcel, info_.sampleId, false);
    WRITEINT32(parcel, info_.collectStrategy, false);
    WRITEINT64(parcel, info_.displayId, false);
    WRITEINT32(parcel, info_.windowId, false);

    WRITEINT32(parcel, static_cast<int32_t>(info_.entityInfo.size()), false);
    for (auto entityItem : info_.entityInfo) {
        WRITESTRING(parcel, entityItem.entityName, false);
        SequenceableUtil::Marshalling(parcel, entityItem.entityInfo);
    }
    return true;
}

SequenceableOnscreenAwarenessInfo* SequenceableOnscreenAwarenessInfo::Unmarshalling(Parcel &parcel)
{
    auto info = new (std::nothrow) SequenceableOnscreenAwarenessInfo();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SequenceableOnscreenAwarenessInfo::ReadFromParcel(Parcel &parcel)
{
    READINT32(parcel, info_.resultCode, false);
    READSTRING(parcel, info_.timestamp, false);
    READSTRING(parcel, info_.bundleName, false);
    READSTRING(parcel, info_.appID, false);
    READINT32(parcel, info_.appIndex, false);
    READSTRING(parcel, info_.pageId, false);
    READSTRING(parcel, info_.sampleId, false);
    READINT32(parcel, info_.collectStrategy, false);
    READINT64(parcel, info_.displayId, false);
    READINT32(parcel, info_.windowId, false);

    int32_t size;
    READINT32(parcel, size, false);
    for (int32_t i = 0; i < size; i++) {
        OnscreenEntityInfo entity;
        READSTRING(parcel, entity.entityName, false);
        SequenceableUtil::Unmarshalling(parcel, entity.entityInfo);
        info_.entityInfo.push_back(entity);
    }
    return true;
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS