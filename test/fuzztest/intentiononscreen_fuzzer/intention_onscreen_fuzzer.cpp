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
#include "on_screen_data.h"
#include "intention_onscreen_fuzzer.h"

#undef LOG_TAG
#define LOG_TAG "IntentionOnscreenFuzzTest"

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

void IntentionOnscreenFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Msdp::DeviceStatus::OnScreen::ContentOption option = {
        .windowId = provider.ConsumeIntegral<int32_t>(),
        .contentUnderstand = provider.ConsumeBool(),
        .pageLink = provider.ConsumeBool(),
        .textOnly = provider.ConsumeBool(),
        .paragraphSizeRange = {
            .minSize = provider.ConsumeIntegral<int32_t>(),
            .maxSize = provider.ConsumeIntegral<int32_t>()
        }
    };
    Msdp::DeviceStatus::OnScreen::PageContent pageContent = {
        .windowId = provider.ConsumeIntegral<int32_t>(),
        .sessionId = provider.ConsumeIntegral<int64_t>(),
        .bundleName = provider.ConsumeRandomLengthString(),
        .scenario = static_cast<OHOS::Msdp::DeviceStatus::OnScreen::Scenario>(
            provider.ConsumeIntegralInRange<int32_t>(0, 2)),
        .title = provider.ConsumeRandomLengthString(),
        .content = provider.ConsumeRandomLengthString(),
        .pageLink = provider.ConsumeRandomLengthString(),
        .paragraphs = {
            {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int64_t>(),
                provider.ConsumeRandomLengthString(), provider.ConsumeRandomLengthString()},
            {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int64_t>(),
                provider.ConsumeRandomLengthString(), provider.ConsumeRandomLengthString()},
        }
    };
    Msdp::DeviceStatus::OnScreen::ControlEvent event = {
        .windowId = provider.ConsumeIntegral<int32_t>(),
        .sessionId = provider.ConsumeIntegral<int64_t>(),
        .eventType = static_cast<OHOS::Msdp::DeviceStatus::OnScreen::EventType>(
            provider.ConsumeIntegralInRange<int32_t>(0, 2)),
        .hookId = provider.ConsumeIntegral<int64_t>()
    };
    INTENTION_CLIENT->GetPageContent(option, pageContent);
    INTENTION_CLIENT->SendControlEvent(event);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::IntentionOnscreenFuzzTest(data, size);

    return 0;
}