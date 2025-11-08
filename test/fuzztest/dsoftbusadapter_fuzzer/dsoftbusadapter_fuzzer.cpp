/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dsoftbusadapter_fuzzer.h"

#include "accesstoken_kit.h"
#include <fuzzer/FuzzedDataProvider.h>
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

bool CheckDeviceOnlineFuzzTest(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeBytesAsString(STR_LEN - 1);
    CircleStreamBuffer circleBuffer;
    StreamBuffer streamBuffer;
    size_t size = 4;
    streamBuffer.wPos_ = provider.ConsumeIntegral<int32_t>();
    streamBuffer.rPos_ = provider.ConsumeIntegral<int32_t>();
    circleBuffer.CheckWrite(size);
    DSoftbusAdapterImpl::GetInstance()->CheckDeviceOnline(networkId);
    DSoftbusAdapterImpl::GetInstance()->HandleSessionData(networkId, circleBuffer);
    DSoftbusAdapterImpl::GetInstance()->OpenSessionLocked(networkId);
    DSoftbusAdapterImpl::GetInstance()->OnConnectedLocked(networkId);
    DSoftbusAdapterImpl::GetInstance()->OpenSession(networkId);
    DSoftbusAdapterImpl::GetInstance()->FindConnection(networkId);
    DSoftbusAdapterImpl::GetInstance()->CheckDeviceOsType(networkId);
    DSoftbusAdapterImpl::GetInstance()->CloseSession(networkId);
    return true;
}


bool SendPacketFuzzTest(FuzzedDataProvider &provider)
{
    Parcel parcel;
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    std::string networkId = provider.ConsumeBytesAsString(STR_LEN - 1);
    DSoftbusAdapterImpl::GetInstance()->SendPacket(networkId, packet);
    DSoftbusAdapterImpl::GetInstance()->SendParcel(networkId, parcel);
    DSoftbusAdapterImpl::GetInstance()->BroadcastPacket(packet);
    DSoftbusAdapterImpl::GetInstance()->HandlePacket(networkId, packet);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::Msdp::DeviceStatus::CheckDeviceOnlineFuzzTest(provider);
    OHOS::Msdp::DeviceStatus::SendPacketFuzzTest(provider);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS