/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "drag_operation_fuzzer.h"

#include "singleton.h"
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "DragOperationFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

namespace OHOS {
const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };

bool StopDragStubFuzzTest(FuzzedDataProvider &provider)
{
    auto buffer = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(buffer.data(), buffer.size()) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::STOP_DRAG), datas, reply, option);
    return true;
}

bool GetDragTargetPidStubFuzzTest(FuzzedDataProvider &provider)
{
    auto buffer = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(buffer.data(), buffer.size()) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_DRAG_TARGET_PID), datas, reply, option);
    return true;
}

bool AddDraglistenerStubFuzzTest(FuzzedDataProvider &provider)
{
    auto buffer = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(buffer.data(), buffer.size()) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::REGISTER_DRAG_MONITOR), datas, reply, option);
    return true;
}

bool RemoverDraglistenerStubFuzzTest(FuzzedDataProvider &provider)
{
    auto buffer = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(buffer.data(), buffer.size()) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::UNREGISTER_DRAG_MONITOR), datas, reply, option);
    return true;
}

bool GethadowOffsetStubFuzzTest(FuzzedDataProvider &provider)
{
    auto buffer = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(buffer.data(), buffer.size()) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_SHADOW_OFFSET), datas, reply, option);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::StopDragStubFuzzTest(provider);
    OHOS::GetDragTargetPidStubFuzzTest(provider);
    OHOS::AddDraglistenerStubFuzzTest(provider);
    OHOS::RemoverDraglistenerStubFuzzTest(provider);
    OHOS::GethadowOffsetStubFuzzTest(provider);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
