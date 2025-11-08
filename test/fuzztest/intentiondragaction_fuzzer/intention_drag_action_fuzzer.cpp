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
#include "intention_drag_action_fuzzer.h"

#undef LOG_TAG
#define LOG_TAG "IntentionDragActionFuzzTest"

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
    Msdp::DeviceStatus::DragSummaryInfo dragSummaryInfo = {
        .summarys = {
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()} // test value
        },
        .detailedSummarys = {
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()} // test value
        },
        .summaryFormat = {
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
        },
        .version = provider.ConsumeIntegral<int32_t>(),
        .totalSize = provider.ConsumeIntegral<int64_t>()
    };
    Msdp::DeviceStatus::DragAction dragAction =
        static_cast<Msdp::DeviceStatus::DragAction>(provider.ConsumeIntegralInRange<uint32_t>(0, 1));

    INTENTION_CLIENT->GetDragAction(dragAction);

    std::string extraInfo = provider.ConsumeBytesAsString(10); // test value
    INTENTION_CLIENT->GetExtraInfo(extraInfo);
    INTENTION_CLIENT->AddPrivilege();
    INTENTION_CLIENT->EraseMouseIcon();
    INTENTION_CLIENT->GetDragSummaryInfo(dragSummaryInfo);
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
