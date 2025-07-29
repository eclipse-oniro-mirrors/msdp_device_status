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

#include "sequenceable_drag_summary_info.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "drag_data_packer.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableDragSummaryInfo"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableDragSummaryInfo::Marshalling(Parcel &parcel) const
{
    CHKEF(SummaryPacker::Marshalling(dragSummaryInfo_.summarys, parcel), "Marshalling summarys failed");
    CHKEF(SummaryPacker::Marshalling(dragSummaryInfo_.detailedSummarys, parcel), "Marshalling detailedSummarys failed");
    CHKEF(SummaryFormat::Marshalling(dragSummaryInfo_.summaryFormat, parcel), "Marshalling summaryFormat failed");
    WRITEINT32(parcel, dragSummaryInfo_.version, false);
    WRITEINT64(parcel, dragSummaryInfo_.totalSize, false);
    return true;
}

SequenceableDragSummaryInfo* SequenceableDragSummaryInfo::Unmarshalling(Parcel &parcel)
{
    SequenceableDragSummaryInfo *sequenceDragSummary = new (std::nothrow) SequenceableDragSummaryInfo();
    CHKPP(sequenceDragSummary);
    if (SummaryPacker::UnMarshalling(parcel, sequenceDragSummary->dragSummaryInfo_.summarys) != RET_OK) {
        FI_HILOGE("UnMarshalling summarys failed");
        delete sequenceDragSummary;
        return nullptr;
    }
    if (SummaryPacker::UnMarshalling(parcel, sequenceDragSummary->dragSummaryInfo_.detailedSummarys) != RET_OK) {
        FI_HILOGE("UnMarshalling detailedSummarys failed");
        delete sequenceDragSummary;
        return nullptr;
    }
    if (SummaryFormat::UnMarshalling(parcel, sequenceDragSummary->dragSummaryInfo_.summaryFormat) != RET_OK) {
        FI_HILOGE("UnMarshalling summaryFormat failed");
        delete sequenceDragSummary;
        return nullptr;
    }
    if (!(parcel).ReadInt32(sequenceDragSummary->dragSummaryInfo_.version)) {
        FI_HILOGE("ReadInt32 version failed");
        delete sequenceDragSummary;
        return nullptr;
    }
    if (!(parcel).ReadInt64(sequenceDragSummary->dragSummaryInfo_.totalSize)) {
        FI_HILOGE("ReadInt64 totalSize failed");
        delete sequenceDragSummary;
        return nullptr;
    }
    return sequenceDragSummary;
}

void SequenceableDragSummaryInfo::GetDragSummaryInfo(DragSummaryInfo &dragSummaryInfo)
{
    dragSummaryInfo = dragSummaryInfo_;
}

void SequenceableDragSummaryInfo::SetDragSummaryInfo(const DragSummaryInfo &dragSummaryInfo)
{
    dragSummaryInfo_ = dragSummaryInfo;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS