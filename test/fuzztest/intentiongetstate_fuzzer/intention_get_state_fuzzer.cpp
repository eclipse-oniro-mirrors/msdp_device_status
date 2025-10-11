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
#include "intention_get_state_fuzzer.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "IntentionGetStateFuzzTest"

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

void FuzzIntentionClientCooperate(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string remoteNetworkId = provider.ConsumeBytesAsString(10); // test value
    int32_t userData = provider.ConsumeIntegral<int32_t>();
    bool checkPermission = provider.ConsumeBool();
    bool state = provider.ConsumeBool();
    uint32_t direction = provider.ConsumeIntegral<uint32_t>();
    double coefficient = provider.ConsumeFloatingPoint<double>();

    INTENTION_CLIENT->GetCooperateStateSync(remoteNetworkId, state);
    INTENTION_CLIENT->GetCooperateStateAsync(remoteNetworkId, userData, checkPermission);
    INTENTION_CLIENT->SetDamplingCoefficient(direction, coefficient);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::FuzzIntentionClientCooperate(data, size);

    return 0;
}
