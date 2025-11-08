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
#include "intention_cooperate_fuzzer.h"

#undef LOG_TAG
#define LOG_TAG "IntentionCooperateFuzzTest"

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

void IntentionCooperateFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t userData = provider.ConsumeIntegral<int32_t>();
    int32_t startDeviceId = provider.ConsumeIntegral<int32_t>();
    bool checkPermission = provider.ConsumeBool();
    bool isUnchained = provider.ConsumeBool();
    std::string remoteNetworkId = provider.ConsumeRandomLengthString();
    std::string networkId = provider.ConsumeRandomLengthString();
    CooperateOptions options  = {
        .displayX = provider.ConsumeIntegral<int32_t>(),
        .displayY = provider.ConsumeIntegral<int32_t>(),
        .displayId = provider.ConsumeIntegral<int32_t>()
    };
    INTENTION_CLIENT->EnableCooperate(userData);
    INTENTION_CLIENT->DisableCooperate(userData);
    INTENTION_CLIENT->EnableCooperate(userData);
    INTENTION_CLIENT->DisableCooperate(userData);
    INTENTION_CLIENT->StartCooperate(remoteNetworkId, userData, startDeviceId, checkPermission);
    INTENTION_CLIENT->StartCooperateWithOptions(remoteNetworkId, userData, startDeviceId,
        checkPermission, options);
    INTENTION_CLIENT->StopCooperate(userData, isUnchained, checkPermission);
    INTENTION_CLIENT->RegisterCooperateListener();
    INTENTION_CLIENT->UnregisterCooperateListener();
    INTENTION_CLIENT->RegisterHotAreaListener(userData, checkPermission);
    INTENTION_CLIENT->UnregisterHotAreaListener(userData, checkPermission);
    INTENTION_CLIENT->RegisterMouseEventListener(networkId);
    INTENTION_CLIENT->UnregisterMouseEventListener(networkId);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::IntentionCooperateFuzzTest(data, size);

    return 0;
}