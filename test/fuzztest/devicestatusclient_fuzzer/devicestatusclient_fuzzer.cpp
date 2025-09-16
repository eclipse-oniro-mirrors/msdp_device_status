/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "devicestatusclient_fuzzer.h"

#include <cstring>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusClientFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t WAIT_TIME { 1000 };

} // namespace

StationaryManager& stationaryMgr = StationaryManager::GetInstance();
sptr<DeviceStatusClientFuzzer::DeviceStatusTestCallback> cb =
    new (std::nothrow) DeviceStatusClientFuzzer::DeviceStatusTestCallback();
void DeviceStatusClientFuzzer::DeviceStatusTestCallback::OnDeviceStatusChanged(const \
    Data& devicestatusData)
{
    std::cout << "DeviceStatusTestCallback type: " << devicestatusData.type << std::endl;
    std::cout << "DeviceStatusTestCallback value: " << devicestatusData.value << std::endl;
}

void DeviceStatusClientFuzzer::TestSubscribeCallback(const uint8_t* data)
{
    std::cout << "TestSubscribeCallback: Enter" << std::endl;
    int32_t type[1];
    int32_t idSize = 4;
    errno_t ret = memcpy_s(type, sizeof(type), data, idSize);
    if (ret != EOK) {
        FI_HILOGE("memcpy_s failed");
        return;
    }

    stationaryMgr.SubscribeCallback(static_cast<Type>(type[0]), ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, cb);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME));
    TestGetDevicestatusData(static_cast<Type>(type[0]));
}

void DeviceStatusClientFuzzer::TestGetDevicestatusData(Type type)
{
    std::cout << "TestGetDevicestatusData: Enter" << std::endl;
    stationaryMgr.GetDeviceStatusData(type);
    DeviceStatus::DevicePostureData postureData;
    stationaryMgr.GetDevicePostureDataSync(postureData);
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME));
    TestUnSubscribeCallback(type);
}

void DeviceStatusClientFuzzer::TestUnSubscribeCallback(Type type)
{
    std::cout << "TestUnSubscribeCallback: Enter" << std::endl;

    stationaryMgr.UnsubscribeCallback(type, ActivityEvent::ENTER_EXIT, cb);
}
bool DeviceStatusClientFuzzTest(FuzzedDataProvider &provider)
{
    return true;
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::Msdp::DeviceStatus::DeviceStatusClientFuzzTest(provider);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS