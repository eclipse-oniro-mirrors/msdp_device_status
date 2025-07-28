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

#ifndef SEQUENCEABLE_DRAG_SUMMARY_INFO_H
#define SEQUENCEABLE_DRAG_SUMMARY_INFO_H

#include <string>
#include <unistd.h>

#include "parcel.h"

#include "drag_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class SequenceableDragSummaryInfo : public Parcelable {
public:
    SequenceableDragSummaryInfo() = default;
    explicit SequenceableDragSummaryInfo(DragSummaryInfo &dragSummaryInfo) : dragSummaryInfo_(dragSummaryInfo) {}
    virtual ~SequenceableDragSummaryInfo() = default;
     
    bool Marshalling(Parcel &parcel) const override;
    static SequenceableDragSummaryInfo* Unmarshalling(Parcel &parcel);
    void GetDragSummaryInfo(DragSummaryInfo &dragSummaryInfo);
    void SetDragSummaryInfo(const DragSummaryInfo &dragSummaryInfo);

private:
    DragSummaryInfo dragSummaryInfo_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_DRAG_SUMMARY_INFO_H