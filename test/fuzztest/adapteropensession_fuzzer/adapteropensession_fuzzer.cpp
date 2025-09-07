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

#include <fuzzer/FuzzedDataProvider.h>
#include "adapteropensession_fuzzer.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "singleton.h"
#include "token_setproc.h"

#include "ddm_adapter.h"
#include "devicestatus_define.h"
#include "dsoftbus_adapter_impl.h"
#include "socket_session_manager.h"

#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "DsoftbusAdapterFuzzTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr size_t STR_LEN = 255;

bool AdapterOpenSessionFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string networkId = provider.ConsumeBytesAsString(STR_LEN);

    DSoftbusAdapterImpl::GetInstance()->OpenSession(networkId);
    DSoftbusAdapterImpl::GetInstance()->FindConnection(networkId);
    DSoftbusAdapterImpl::GetInstance()->CloseSession(networkId);

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if ((data == nullptr) || (size < 1)) {
        return 0;
    }

    OHOS::Msdp::DeviceStatus::AdapterOpenSessionFuzzTest(data, size);

    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS