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

#include "devicestatussrvstub_fuzzer.h"

#include "singleton.h"

#define private public
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusStubSrvFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OHOS {
const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };

bool StopDragStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::STOP_DRAG), datas, reply, option);
    return true;
}

bool GetDragTargetPidFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_DRAG_TARGET_PID), datas, reply, option);
    return true;
}

bool AddDraglistenerStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::REGISTER_DRAG_MONITOR), datas, reply, option);
    return true;
}

bool RemoverDraglistenerStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::UNREGISTER_DRAG_MONITOR), datas, reply, option);
    return true;
}

bool GethadowOffsetStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_SHADOW_OFFSET), datas, reply, option);
    return true;
}

bool GetDragStateStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_DRAG_STATE), datas, reply, option);
    return true;
}

bool GetDragSummaryStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_DRAG_SUMMARY), datas, reply, option);
    return true;
}

bool GetDragExtraInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_DRAG_EXTRAINFO), datas, reply, option);
    return true;
}

bool GetDragActionStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::GET_DRAG_ACTION), datas, reply, option);
    return true;
}

bool UpdatePreviewStyleStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::UPDATE_PREVIEW_STYLE), datas, reply, option);
    return true;
}

bool UpdatePreviewStyleWithAnimationStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::UPDATE_PREVIEW_STYLE_WITH_ANIMATION), datas, reply, option);
    return true;
}

bool AddPrivilegeStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::ADD_PRIVILEGE), datas, reply, option);
    return true;
}

bool EraseMouseIconStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::DeviceInterfaceCode::ERASE_MOUSE_ICON), datas, reply, option);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::StopDragStubFuzzTest(data, size);
    OHOS::GetDragTargetPidFuzzTest(data, size);
    OHOS::AddDraglistenerStubFuzzTest(data, size);
    OHOS::RemoverDraglistenerStubFuzzTest(data, size);
    OHOS::GethadowOffsetStubFuzzTest(data, size);
    OHOS::GetDragStateStubFuzzTest(data, size);
    OHOS::GetDragSummaryStubFuzzTest(data, size);
    OHOS::GetDragExtraInfoStubFuzzTest(data, size);
    OHOS::GetDragActionStubFuzzTest(data, size);
    OHOS::UpdatePreviewStyleStubFuzzTest(data, size);
    OHOS::UpdatePreviewStyleWithAnimationStubFuzzTest(data, size);
    OHOS::AddPrivilegeStubFuzzTest(data, size);
    OHOS::EraseMouseIconStubFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS