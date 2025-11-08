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

#include "devicestatus_callback_stub.h"
#include "intention_client.h"
#include "intention_stationary_fuzzer.h"
#include "stationary_data.h"

#undef LOG_TAG
#define LOG_TAG "IntentionStationaryFuzzTest"

namespace {
    constexpr size_t THRESHOLD = 5;
}
using namespace OHOS::Media;
using namespace OHOS::Msdp::DeviceStatus;

class StationaryServerTestCallback : public OHOS::Msdp::DeviceStatus::DeviceStatusCallbackStub {
    public:
        void OnDeviceStatusChanged(const Data &value) override {}
    };

namespace OHOS {

void IntentionStationaryFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t type = provider.ConsumeIntegral<int32_t>();
    int32_t replyType = provider.ConsumeIntegral<int32_t>();
    int32_t replyValue = provider.ConsumeIntegral<int32_t>();
    Msdp::DeviceStatus::DevicePostureData postureData = {
        .rollRad = provider.ConsumeFloatingPoint<float>(),
        .pitchRad = provider.ConsumeFloatingPoint<float>(),
        .yawRad = provider.ConsumeFloatingPoint<float>()
    };
    INTENTION_CLIENT->GetDeviceStatusData(type, replyType, replyValue);
    INTENTION_CLIENT->GetDevicePostureDataSync(postureData);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::IntentionStationaryFuzzTest(data, size);

    return 0;
}