/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "devicestatus_srv_proxy.h"
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
#include "hitrace_meter.h"
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
#include "iremote_object.h"
#include <message_option.h>
#include <message_parcel.h>

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "drag_data_packer.h"
#include "preview_style_packer.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusSrvProxy"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DeviceStatusSrvProxy::Subscribe(Type type, ActivityEvent event, ReportLatencyNs latency,
    sptr<IRemoteDevStaCallback> callback)
{
    CALL_DEBUG_ENTER;
    FI_HILOGI("Enter event:%{public}d, latency:%{public}d", event, latency);
    sptr<IRemoteObject> remote = Remote();
    DEV_RET_IF_NULL((remote == nullptr) || (callback == nullptr));

    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return;
    }

    WRITEINT32(data, type);
    WRITEINT32(data, event);
    WRITEINT32(data, latency);
    WRITEREMOTEOBJECT(data, callback->AsObject());

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::DEVICESTATUS_SUBSCRIBE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, errCode:%{public}d", ret);
        return;
    }
}

void DeviceStatusSrvProxy::Unsubscribe(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("Enter, event:%{public}d", event);
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
    StartTrace(HITRACE_TAG_MSDP, "clientUnSubscribeStart");
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
    sptr<IRemoteObject> remote = Remote();
    DEV_RET_IF_NULL((remote == nullptr) || (callback == nullptr));

    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return;
    }
    WRITEINT32(data, type);
    WRITEINT32(data, event);
    WRITEREMOTEOBJECT(data, callback->AsObject());

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::DEVICESTATUS_UNSUBSCRIBE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, errCode:%{public}d", ret);
        return;
    }
}

Data DeviceStatusSrvProxy::GetCache(const Type &type)
{
    CALL_DEBUG_ENTER;
    Data devicestatusData;
    devicestatusData.type = Type::TYPE_INVALID;
    devicestatusData.value = OnChangedValue::VALUE_INVALID;

    sptr<IRemoteObject> remote = Remote();
    DEV_RET_IF_NULL_WITH_RET((remote == nullptr), devicestatusData);

    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return devicestatusData;
    }
    WRITEINT32(data, type, devicestatusData);
    
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::DEVICESTATUS_GETCACHE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, errCode:%{public}d", ret);
        return devicestatusData;
    }

    int32_t devicestatusType = -1;
    int32_t devicestatusValue = -1;
    READINT32(reply, devicestatusType, devicestatusData);
    READINT32(reply, devicestatusValue, devicestatusData);
    devicestatusData.type = static_cast<Type>(devicestatusType);
    devicestatusData.value = static_cast<OnChangedValue>(devicestatusValue);
    FI_HILOGD("type:%{public}d, value:%{public}d", devicestatusData.type, devicestatusData.value);
    return devicestatusData;
}

int32_t DeviceStatusSrvProxy::RegisterCoordinationListener(bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::REGISTER_COOPERATE_MONITOR),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::REGISTER_COORDINATION_MONITOR),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::UnregisterCoordinationListener(bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;
    MessageParcel reply;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UNREGISTER_COOPERATE_MONITOR),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UNREGISTER_COORDINATION_MONITOR),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::PrepareCoordination(int32_t userData, bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;
    MessageParcel reply;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::PREPARE_COOPERATE),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::PREPARE_COORDINATION),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::UnprepareCoordination(int32_t userData, bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UNPREPARE_COOPERATE),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UNPREPARE_COORDINATION),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::ActivateCoordination(int32_t userData, const std::string &remoteNetworkId,
    int32_t startDeviceId, bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    WRITESTRING(data, remoteNetworkId, ERR_INVALID_VALUE);
    WRITEINT32(data, startDeviceId, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::START_COOPERATE),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::START_COORDINATION),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::DeactivateCoordination(int32_t userData, bool isUnchained, bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    WRITEBOOL(data, isUnchained, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::STOP_COOPERATE),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::STOP_COORDINATION),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::UpdateDragStyle(DragCursorStyle style)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, static_cast<int32_t>(style), ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UPDATED_DRAG_STYLE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetDragTargetPid()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken failed");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_TARGET_PID),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    int32_t pid = 0;
    READINT32(reply, pid, IPC_PROXY_DEAD_OBJECT_ERR);
    return pid;
}

int32_t DeviceStatusSrvProxy::GetUdKey(std::string &udKey)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken failed");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_TARGET_UDKEY),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    READSTRING(reply, udKey, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t DeviceStatusSrvProxy::GetDragData(DragData &dragData)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;
    MessageParcel reply;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_DATA), data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, IPC_PROXY_DEAD_OBJECT_ERR);
    if (ret != RET_OK) {
        FI_HILOGE("Get DragData failed");
        return ret;
    }
    if (DragDataPacker::UnMarshalling(reply, dragData) != RET_OK) {
        FI_HILOGE("UnMarshalling dragData failed");
        return RET_ERR;
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetDragState(DragState &dragState)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_STATE), data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }

    int32_t dragStateTmp = 0;
    READINT32(reply, dragStateTmp, E_DEVICESTATUS_READ_PARCEL_ERROR);
    dragState = static_cast<DragState>(dragStateTmp);
    return ret;
}

int32_t DeviceStatusSrvProxy::GetCoordinationState(int32_t userData,
    const std::string &networkId, bool isCompatible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    WRITESTRING(data, networkId, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = -1;
    if (isCompatible) {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_COOPERATE_STATE),
            data, reply, option);
    } else {
        ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_COORDINATION_STATE),
            data, reply, option);
    }
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetCoordinationState(const std::string &udId, bool &state)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITESTRING(data, udId, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_COORDINATION_STATE_SYNC),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    READBOOL(reply, state, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t DeviceStatusSrvProxy::StartDrag(const DragData &dragData)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (DragDataPacker::Marshalling(dragData, data) != RET_OK) {
        FI_HILOGE("Failed to marshalling dragData");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::START_DRAG),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    READINT32(reply, ret, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t DeviceStatusSrvProxy::StopDrag(const DragDropResult &dropResult)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (dropResult.result < DragResult::DRAG_SUCCESS || dropResult.result > DragResult::DRAG_EXCEPTION) {
        FI_HILOGE("Invalid result:%{public}d", static_cast<int32_t>(dropResult.result));
        return RET_ERR;
    }
    WRITEINT32(data, static_cast<int32_t>(dropResult.result), ERR_INVALID_VALUE);
    WRITEBOOL(data, dropResult.hasCustomAnimation, ERR_INVALID_VALUE);
    WRITEINT32(data, dropResult.mainWindow, ERR_INVALID_VALUE);
    WRITEINT32(data, static_cast<int32_t>(dropResult.dragBehavior), ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::STOP_DRAG),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    READINT32(reply, ret, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t DeviceStatusSrvProxy::AllocSocketFd(const std::string &programName, int32_t moduleType,
    int32_t &socketFd, int32_t &tokenType)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, moduleType, ERR_INVALID_VALUE);
    WRITESTRING(data, programName, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::ALLOC_SOCKET_FD),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    socketFd = reply.ReadFileDescriptor();
    if (socketFd < RET_OK) {
        FI_HILOGE("Read file descriptor failed, fd:%{public}d", socketFd);
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    READINT32(reply, tokenType, IPC_PROXY_DEAD_OBJECT_ERR);
    FI_HILOGD("socketFd:%{public}d, tokenType:%{public}d", socketFd, tokenType);
    return RET_OK;
}

int32_t DeviceStatusSrvProxy::AddDraglistener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::REGISTER_DRAG_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::RemoveDraglistener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UNREGISTER_DRAG_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::AddSubscriptListener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::REGISTER_SUBSCRIPT_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::RemoveSubscriptListener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UNREGISTER_SUBSCRIPT_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::SetDragWindowVisible(bool visible, bool isForce)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, visible, ERR_INVALID_VALUE);
    WRITEBOOL(data, isForce, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::SET_DRAG_WINDOW_VISIBLE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetShadowOffset(ShadowOffset &shadowOffset)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_SHADOW_OFFSET),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    if (ShadowOffsetPacker::UnMarshalling(reply, shadowOffset) != RET_OK) {
        FI_HILOGE("UnMarshalling offset failed");
        return RET_ERR;
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (ShadowPacker::PackUpShadowInfo(shadowInfo, data) != RET_OK) {
        FI_HILOGE("PackUpShadowInfo failed");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UPDATE_SHADOW_PIC),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::AddHotAreaListener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::ADD_HOT_AREA_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::RemoveHotAreaListener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::REMOVE_HOT_AREA_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (PreviewStylePacker::Marshalling(previewStyle, data) != RET_OK) {
        FI_HILOGE("Marshalling previewStyle failed");
        return RET_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UPDATE_PREVIEW_STYLE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
    const PreviewAnimation &animation)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (PreviewStylePacker::Marshalling(previewStyle, data) != RET_OK) {
        FI_HILOGE("Marshalling previewStyle failed");
        return RET_ERR;
    }
    if (PreviewAnimationPacker::Marshalling(animation, data) != RET_OK) {
        FI_HILOGE("Marshalling animation failed");
        return RET_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::UPDATE_PREVIEW_STYLE_WITH_ANIMATION),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetDragSummary(std::map<std::string, int64_t> &summarys)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_SUMMARY),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    if (SummaryPacker::UnMarshalling(reply, summarys) != RET_OK) {
        FI_HILOGE("Failed to summarys unmarshalling");
        return RET_ERR;
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetDragAction(DragAction &dragAction)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_ACTION),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    int32_t type;
    READINT32(reply, type, IPC_PROXY_DEAD_OBJECT_ERR);
    dragAction = static_cast<DragAction>(type);
    return ret;
}

int32_t DeviceStatusSrvProxy::EnterTextEditorArea(bool enable)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, enable, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::ENTER_TEXT_EDITOR_AREA),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::GetExtraInfo(std::string &extraInfo)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::GET_DRAG_EXTRAINFO),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READSTRING(reply, extraInfo, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t DeviceStatusSrvProxy::AddPrivilege()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::ADD_PRIVILEGE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return ret;
}

int32_t DeviceStatusSrvProxy::EraseMouseIcon()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DeviceStatusSrvProxy::GetDescriptor())) {
        FI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(DeviceInterfaceCode::ERASE_MOUSE_ICON),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return ret;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
