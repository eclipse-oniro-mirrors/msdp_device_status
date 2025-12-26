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

#include "sequenceablecooperateoptions_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"

#define private public
#include "sequenceable_content_option.h"
#include "sequenceable_control_event.h"
#include "sequenceable_cooperate_options.h"
#include "sequenceable_drag_data.h"
#include "sequenceable_drag_result.h"
#include "sequenceable_drag_summary_info.h"
#include "sequenceable_drag_visible.h"
#include "sequenceable_page_content.h"
#include "sequenceable_posture_data.h"
#include "sequenceable_preview_animation.h"
#include "sequenceable_preview_style.h"
#include "sequenceable_rotate_window.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableCooperateOptionsFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t RANGEMAX = 10;
}
bool SequenceableCooperateOptionsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Parcel parcel;
    CooperateOptions options = {
        .displayX = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .displayY = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .displayId = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
    };
    SequenceableCooperateOptions cooperateOptions(options);
    SequenceableCooperateOptions *cooperateOptions1 = cooperateOptions.Unmarshalling(parcel);
    if (cooperateOptions1 != nullptr) {
        cooperateOptions1->Marshalling(parcel);
    }
    return true;
}

bool SequenceableDragDataFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Parcel parcel;
    Msdp::DeviceStatus::DragData dragData {
        .buffer = {
            provider.ConsumeIntegral<uint8_t>(),
            provider.ConsumeIntegral<uint8_t>()
        },
        .udKey = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .extraInfo = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .filterInfo = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .sourceType = provider.ConsumeIntegral<int32_t>(),
        .dragNum = provider.ConsumeIntegral<int32_t>(),
        .pointerId = provider.ConsumeIntegral<int32_t>(),
        .displayX = provider.ConsumeIntegral<int32_t>(),
        .displayY = provider.ConsumeIntegral<int32_t>(),
        .displayId = provider.ConsumeIntegral<int32_t>(),
        .mainWindow = provider.ConsumeIntegral<int32_t>(),
        .hasCanceledAnimation = provider.ConsumeBool(),
        .hasCoordinateCorrected = provider.ConsumeBool(),
        .isDragDelay = provider.ConsumeBool(),
        .summaryVersion = provider.ConsumeIntegral<int32_t>(),
        .summaryTotalSize = provider.ConsumeIntegral<int64_t>(),
        .appCallee = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .appCaller = provider.ConsumeBytesAsString(RANGEMAX) // test value
    };
    SequenceableDragData sequenceableDragData(dragData);
    SequenceableDragData *sequenceableDragData1 =  sequenceableDragData.Unmarshalling(parcel);
    if (sequenceableDragData1 != nullptr) {
        sequenceableDragData1->Marshalling(parcel);
    }
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    SequenceableCooperateOptionsFuzzTest(data, size);
    SequenceableDragDataFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS