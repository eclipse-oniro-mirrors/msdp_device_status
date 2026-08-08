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

#ifndef SEQUENCEABLE_CAR_AWARENESS_OPTION_H
#define SEQUENCEABLE_CAR_AWARENESS_OPTION_H

#include "parcel.h"
#include "car_awareness_type.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequenceableCarAwarenessOption : public Parcelable {
public:
    SequenceableCarAwarenessOption() = default;
    explicit SequenceableCarAwarenessOption(const CarAwarenessOption &option) : option_(option) {}
    virtual ~SequenceableCarAwarenessOption() = default;

    bool Marshalling(Parcel &parcel) const override;
    static SequenceableCarAwarenessOption* Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);
    CarAwarenessOption option_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_CAR_AWARENESS_OPTION_H