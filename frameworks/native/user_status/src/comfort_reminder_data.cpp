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

#include "comfort_reminder_data.h"

#include "message_parcel.h"

#include "devicestatus_define.h"
#include "fi_log.h"


namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
ComfortReminderData::ComfortReminderData() {}

ComfortReminderData::~ComfortReminderData() {}

int32_t ComfortReminderData::GetFusionReminderData() const
{
    return fusionReminderData_;
}

void ComfortReminderData::SetFusionReminderData(const int32_t fusionReminderData)
{
    fusionReminderData_ = fusionReminderData;
}

int32_t ComfortReminderData::GetSwingReminderData() const
{
    return swingReminderData_;
}

void ComfortReminderData::SetSwingReminderData(const int32_t swingReminderData)
{
    swingReminderData_ = swingReminderData;
}

int32_t ComfortReminderData::GetEventType() const
{
    return eventType_;
}

void ComfortReminderData::SetEventType(const int32_t eventType)
{
    eventType_ = eventType;
}

std::string ComfortReminderData::Dump()
{
    std::string dumpInfo = DumpBaseData();
    dumpInfo.append(", fusionReminderData_=");
    dumpInfo.append(std::to_string(fusionReminderData_));
    dumpInfo.append(", swingReminderData_=");
    dumpInfo.append(std::to_string(swingReminderData_));
    dumpInfo.append(", eventType_=");
    dumpInfo.append(std::to_string(eventType_));
    return dumpInfo;
}

std::shared_ptr<UserStatusData> ComfortReminderData::Unmarshalling(Parcel &parcel)
{
    auto data = std::make_shared<ComfortReminderData>();
    if (!data->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        return nullptr;
    }
    return data;
}

bool ComfortReminderData::MarshallComfortReminderData(Parcel &parcel) const
{
    CHKBRF(parcel.WriteInt32(fusionReminderData_));
    CHKBRF(parcel.WriteInt32(swingReminderData_));
    CHKBRF(parcel.WriteInt32(eventType_));

    return true;
}

bool ComfortReminderData::Marshalling(Parcel &parcel) const
{
    CHKBRF(parcel.WriteUint32(feature_));
    CHKBRF(parcel.WriteInt32(result_));
    CHKBRF(parcel.WriteInt32(errorCode_));
    CHKBRF(parcel.WriteString(status_));
    if (!MarshallComfortReminderData(parcel)) {
        FI_HILOGE("write ComfortReminderData failed");
        return false;
    }

    return true;
}

bool ComfortReminderData::ReadFromParcel(Parcel &parcel)
{
    result_ = parcel.ReadInt32();
    errorCode_ = parcel.ReadInt32();
    status_ = parcel.ReadString();
    if (status_.empty()) {
        FI_HILOGE("Read status_ failed");
        return false;
    }
    fusionReminderData_ = parcel.ReadInt32();
    swingReminderData_ = parcel.ReadInt32();
    eventType_ = parcel.ReadInt32();
    return true;
}
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
