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

#include "sequenceable_feedback_data.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableFeedbackData"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
bool SequenceableFeedbackData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(data_.perceptionEventId)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(data_.feedbackType))) {
        return false;
    }
    if (!parcel.WriteInt64(data_.feedbackTime)) {
        return false;
    }
    return true;
}

bool SequenceableFeedbackData::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(data_.perceptionEventId)) {
        return false;
    }
    int32_t feedbackType = 0;
    if (!parcel.ReadInt32(feedbackType)) {
        return false;
    }
    data_.feedbackType = static_cast<FeedbackType>(feedbackType);
    if (!parcel.ReadInt64(data_.feedbackTime)) {
        return false;
    }
    return true;
}

SequenceableFeedbackData *SequenceableFeedbackData::Unmarshalling(Parcel &parcel)
{
    auto *data = new (std::nothrow) SequenceableFeedbackData();
    if (data != nullptr && !data->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        delete data;
        data = nullptr;
    }
    return data;
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
