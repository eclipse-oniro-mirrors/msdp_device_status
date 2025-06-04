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

#ifndef SEQUENCEABLE_COOPERATE_OPTIONS_H
#define SEQUENCEABLE_COOPERATE_OPTIONS_H
 
#include <string>
#include <unistd.h>
 
#include "coordination_message.h"
#include "nocopyable.h"
#include "parcel.h"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
class SequenceableCooperateOptions : public Parcelable {
public:
    SequenceableCooperateOptions() = default;
    explicit SequenceableCooperateOptions(const CooperateOptions &options) : options_(options) {}
    virtual ~SequenceableCooperateOptions() = default;
     
    bool Marshalling(Parcel &parcel) const override;
    static SequenceableCooperateOptions* Unmarshalling(Parcel &parcel);
 
public:
    CooperateOptions options_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_COOPERATE_OPTIONS_H