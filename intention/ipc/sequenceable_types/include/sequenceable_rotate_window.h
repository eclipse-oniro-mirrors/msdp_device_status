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

#ifndef SEQUENCEABLE_ROTATE_WINDOW_H
#define SEQUENCEABLE_ROTATE_WINDOW_H

#include <string>
#include <unistd.h>

#include "nocopyable.h"

#include "transaction/rs_transaction.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class SequenceableRotateWindow : public Parcelable {
public:
    SequenceableRotateWindow() = default;
    explicit SequenceableRotateWindow(std::shared_ptr<Rosen::RSTransaction> rsTransaction)
        : rsTransaction_(rsTransaction) {}
    virtual ~SequenceableRotateWindow() = default;
     
    bool Marshalling(Parcel &parcel) const override;
    static SequenceableRotateWindow* Unmarshalling(Parcel &parcel);

public:
    std::shared_ptr<Rosen::RSTransaction> rsTransaction_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_ROTATE_WINDOW_H