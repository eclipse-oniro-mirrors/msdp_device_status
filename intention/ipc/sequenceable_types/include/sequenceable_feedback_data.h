/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SEQUENCEABLE_FEEDBACK_DATA_H
#define SEQUENCEABLE_FEEDBACK_DATA_H

#include "parcel.h"
#include "behavior_awareness_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
class SequenceableFeedbackData : public Parcelable {
public:
    SequenceableFeedbackData() = default;
    explicit SequenceableFeedbackData(const FeedbackData &data) : data_(data) {}
    virtual ~SequenceableFeedbackData() = default;

    bool Marshalling(Parcel &parcel) const override;
    static SequenceableFeedbackData *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);

    FeedbackData data_;
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_FEEDBACK_DATA_H
