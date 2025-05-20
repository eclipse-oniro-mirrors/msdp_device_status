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

#ifndef SEQUENCEABLE_DRAG_VISIBLE_H
#define SEQUENCEABLE_DRAG_VISIBLE_H

#include <string>
#include <unistd.h>

#include "nocopyable.h"
#include "parcel.h"

#include "transaction/rs_transaction.h"

#include "drag_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct DragVisibleParam {
    bool visible { false };
    bool isForce { false };
    std::shared_ptr<Rosen::RSTransaction> rsTransaction { nullptr };
};

class SequenceableDragVisible : public Parcelable {
public:
    SequenceableDragVisible() = default;
    explicit SequenceableDragVisible(const DragVisibleParam &dragVisibleParam)
        : dragVisibleParam_(dragVisibleParam) {}
    virtual ~SequenceableDragVisible() = default;
     
    bool Marshalling(Parcel &parcel) const override;
    static SequenceableDragVisible* Unmarshalling(Parcel &parcel);

public:
    DragVisibleParam dragVisibleParam_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_DRAG_VISIBLE_H