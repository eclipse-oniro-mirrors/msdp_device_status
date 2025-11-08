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

#include "dsoftbussession_fuzzer.h"

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
#define LOG_TAG "DsoftbusSessionFuzzTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
#define SERVER_SESSION_NAME "ohos.msdp.device_status.intention.serversession"
constexpr size_t STR_LEN = 255;
constexpr size_t PKG_NAME_SIZE_MAX { 65 };
constexpr size_t DEVICE_NAME_SIZE_MAX { 256 };

bool InitSocketFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    int32_t socketType = provider.ConsumeIntegral<int32_t>();
    int32_t dataLen = provider.ConsumeIntegral<int32_t>();
    std::string networkId =  provider.ConsumeRandomLengthString(STR_LEN - 1);
    int32_t *g_data = new int32_t(socket);
    ShutdownReason reason =
        static_cast<ShutdownReason>(provider.ConsumeIntegralInRange<int32_t>(0, SHUTDOWN_REASON_UNEXPECTED));
    char name[DEVICE_NAME_SIZE_MAX] { SERVER_SESSION_NAME };
    char pkgName[PKG_NAME_SIZE_MAX] { FI_PKG_NAME };
    SocketInfo info {
        .name = name,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };
    PeerSocketInfo info1 {
        .networkId = networkId.data(),
    };
    DSoftbusAdapterImpl::GetInstance()->SetSocketOpt(socket);
    DSoftbusAdapterImpl::GetInstance()->InitSocket(info, socketType, socket);
    DSoftbusAdapterImpl::GetInstance()->ConfigTcpAlive(socket);
    DSoftbusAdapterImpl::GetInstance()->OnShutdown(socket, reason);
    DSoftbusAdapterImpl::GetInstance()->OnBytes(socket, g_data, dataLen);
    DSoftbusAdapterImpl::GetInstance()->OnBind(socket, info1);
    DSoftbusAdapterImpl::GetInstance()->HandleRawData(networkId, g_data, dataLen);
    delete g_data;
    return true;
}

bool SendHeartBeatFuzzTest(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeBytesAsString(STR_LEN-1);
    bool state = provider.ConsumeBool();
    DSoftbusAdapterImpl::GetInstance()->InitHeartBeat();
    DSoftbusAdapterImpl::GetInstance()->FindConnection(networkId);
    DSoftbusAdapterImpl::GetInstance()->HasSessionExisted(networkId);
    DSoftbusAdapterImpl::GetInstance()->StartHeartBeat(networkId);
    DSoftbusAdapterImpl::GetInstance()->GetHeartBeatState(networkId);
    DSoftbusAdapterImpl::GetInstance()->KeepHeartBeating(networkId);
    DSoftbusAdapterImpl::GetInstance()->UpdateHeartBeatState(networkId, state);
    DSoftbusAdapterImpl::GetInstance()->StopHeartBeat(networkId);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::Msdp::DeviceStatus::InitSocketFuzzTest(provider);
    OHOS::Msdp::DeviceStatus::SendHeartBeatFuzzTest(provider);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS