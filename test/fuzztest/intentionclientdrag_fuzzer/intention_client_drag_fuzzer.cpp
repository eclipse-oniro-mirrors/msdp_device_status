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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <nocopyable.h>

#include "boomerang_callback_stub.h"
#include "devicestatus_callback_stub.h"
#include "intention_client.h"
#include "intention_client_drag_fuzzer.h"

#undef LOG_TAG
#define LOG_TAG "IntentionClientDragFuzzTest"

namespace {
    constexpr size_t THRESHOLD = 5;
}
using namespace OHOS::Media;
using namespace OHOS::Msdp;

class BoomerangClientTestCallback : public OHOS::Msdp::DeviceStatus::BoomerangCallbackStub {
public:

private:
    OHOS::Msdp::DeviceStatus::BoomerangData data_;
};

namespace OHOS {

void FuzzIntentionClientDrag(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Msdp::DeviceStatus::DragDropResult dragDropResult {
        .hasCustomAnimation = provider.ConsumeBool(),
        .mainWindow = provider.ConsumeIntegral<int32_t>()
    };
    Msdp::DeviceStatus::DragData dragData {
        .buffer = {
            provider.ConsumeIntegral<uint8_t>(),
            provider.ConsumeIntegral<uint8_t>()
        },
        .udKey = provider.ConsumeBytesAsString(10), // test value
        .extraInfo = provider.ConsumeBytesAsString(10), // test value
        .filterInfo = provider.ConsumeBytesAsString(10), // test value
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
        .appCallee = provider.ConsumeBytesAsString(10), // test value
        .appCaller = provider.ConsumeBytesAsString(10) // test value
    };

    INTENTION_CLIENT->StartDrag(dragData);
    INTENTION_CLIENT->GetDragData(dragData);
    INTENTION_CLIENT->StopDrag(dragDropResult);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::FuzzIntentionClientDrag(data, size);
    return 0;
}
