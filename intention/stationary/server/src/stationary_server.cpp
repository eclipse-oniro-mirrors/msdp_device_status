/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "stationary_server.h"
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include "hisysevent.h"
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
#include "hitrace_meter.h"
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE

#include "default_params.h"
#include "devicestatus_define.h"
#include "devicestatus_dumper.h"
#include "devicestatus_hisysevent.h"
#include "stationary_data.h"
#include "stationary_params.h"

#undef LOG_TAG
#define LOG_TAG "StationaryServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
#ifdef MOTION_ENABLE
constexpr int32_t MOTION_TYPE_STAND = 3602;
constexpr int32_t STATUS_ENTER = 1;
constexpr int32_t STATUS_EXIT = 0;
std::map<Type, int32_t> MOTION_TYPE_MAP {
    { Type::TYPE_STAND, MOTION_TYPE_STAND },
};
std::map<int32_t, Type> DEVICE_STATUS_TYPE_MAP {
    { MOTION_TYPE_STAND, Type::TYPE_STAND },
};
#else
constexpr int32_t RET_NO_SUPPORT = 801;
#endif
} // namespace

#ifdef MOTION_ENABLE
void MotionCallback::OnMotionChanged(const MotionEvent &motionEvent)
{
    Data data;
    data.type = DEVICE_STATUS_TYPE_MAP[motionEvent.type];
    switch (motionEvent.status) {
        case STATUS_ENTER:
            data.value = VALUE_ENTER;
            break;
        case STATUS_EXIT:
            data.value = VALUE_EXIT;
            break;
        default:
            data.value = VALUE_INVALID;
            break;
    }
    event_(data);
}

void RemoteDevStaCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    event_(remote);
}
#endif

StationaryServer::StationaryServer()
{
    manager_.Init();
#ifdef MOTION_ENABLE
    auto deathRecipientCB = [this](const wptr<IRemoteObject> &remote) {
        this->StationaryServerDeathRecipient(remote);
    };
    devStaCBDeathRecipient_ = new (std::nothrow) RemoteDevStaCallbackDeathRecipient(deathRecipientCB);
#endif
}

int32_t StationaryServer::Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t StationaryServer::Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t StationaryServer::Start(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t StationaryServer::Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t StationaryServer::AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    if (id != StationaryRequestID::SUBSCRIBE_STATIONARY) {
        FI_HILOGE("Unexpected request ID (%{public}u)", id);
        return RET_ERR;
    }
    SubscribeStationaryParam param {};

    if (!param.Unmarshalling(data)) {
        FI_HILOGE("SubscribeStationaryParam::Unmarshalling fail");
        return RET_ERR;
    }
    if (param.type_ == Type::TYPE_STAND) {
#ifdef MOTION_ENABLE
        return SubscribeMotion(param.type_, param.callback_);
#else
        return RET_NO_SUPPORT;
#endif
    } else {
        Subscribe(context, param.type_, param.event_, param.latency_, param.callback_);
    }
    return RET_OK;
}

int32_t StationaryServer::RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    if (id != StationaryRequestID::UNSUBSCRIBE_STATIONARY) {
        FI_HILOGE("Unexpected request ID (%{public}u)", id);
        return RET_ERR;
    }
    UnsubscribeStationaryParam param {};

    if (!param.Unmarshalling(data)) {
        FI_HILOGE("UnsubscribeStationaryParam::Unmarshalling fail");
        return RET_ERR;
    }
    if (param.type_ == Type::TYPE_STAND) {
#ifdef MOTION_ENABLE
        return UnsubscribeMotion(param.type_, param.callback_);
#else
        return RET_NO_SUPPORT;
#endif
    } else {
        Unsubscribe(context, param.type_, param.event_, param.callback_);
    }
    return RET_OK;
}

int32_t StationaryServer::SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t StationaryServer::GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    if (id != StationaryRequestID::GET_STATIONARY_DATA) {
        FI_HILOGE("Unexpected request ID (%{public}u)", id);
        return RET_ERR;
    }
    GetStaionaryDataParam param {};

    if (!param.Unmarshalling(data)) {
        FI_HILOGE("GetStaionaryDataParam::Unmarshalling fail");
        return RET_ERR;
    }
    GetStaionaryDataReply dataReply { GetCache(context, param.type_) };
    if (!dataReply.Marshalling(reply)) {
        FI_HILOGE("GetStaionaryDataReply::Marshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t StationaryServer::Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

void StationaryServer::DumpDeviceStatusSubscriber(int32_t fd) const
{
    DS_DUMPER->DumpDeviceStatusSubscriber(fd);
}

void StationaryServer::DumpDeviceStatusChanges(int32_t fd) const
{
    DS_DUMPER->DumpDeviceStatusChanges(fd);
}

void StationaryServer::DumpCurrentDeviceStatus(int32_t fd)
{
    std::vector<Data> datas;

    for (auto type = TYPE_ABSOLUTE_STILL; type <= TYPE_LID_OPEN; type = static_cast<Type>(type + 1)) {
        Data data = manager_.GetLatestDeviceStatusData(type);
        if (data.value != OnChangedValue::VALUE_INVALID) {
            datas.emplace_back(data);
        }
    }
    DS_DUMPER->DumpDeviceStatusCurrentStatus(fd, datas);
}

void StationaryServer::Subscribe(CallingContext &context, Type type, ActivityEvent event,
    ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback)
{
    FI_HILOGI("SubscribeStationary(type:%{public}d,event:%{public}d,latency:%{public}d)", type, event, latency);
    auto appInfo = std::make_shared<AppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    manager_.GetPackageName(appInfo->tokenId, appInfo->packageName);
    appInfo->type = type;
    appInfo->callback = callback;
    DS_DUMPER->SaveAppInfo(appInfo);
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
    StartTrace(HITRACE_TAG_MSDP, "serviceSubscribeStart");
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
    manager_.Subscribe(type, event, latency, callback);
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
    FinishTrace(HITRACE_TAG_MSDP);
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
    ReportSensorSysEvent(context, type, true);
    WriteSubscribeHiSysEvent(appInfo->uid, appInfo->packageName, type);
}

void StationaryServer::Unsubscribe(CallingContext &context, Type type,
    ActivityEvent event, sptr<IRemoteDevStaCallback> callback)
{
    FI_HILOGI("UnsubscribeStationary(type:%{public}d,event:%{public}d)", type, event);
    auto appInfo = std::make_shared<AppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->type = type;
    appInfo->callback = callback;
    DS_DUMPER->RemoveAppInfo(appInfo);
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
    StartTrace(HITRACE_TAG_MSDP, "serviceUnSubscribeStart");
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
    manager_.Unsubscribe(type, event, callback);
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
    FinishTrace(HITRACE_TAG_MSDP);
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
    ReportSensorSysEvent(context, type, false);
    WriteUnSubscribeHiSysEvent(appInfo->uid, appInfo->packageName, type);
}

Data StationaryServer::GetCache(CallingContext &context, const Type &type)
{
    return manager_.GetLatestDeviceStatusData(type);
}

void StationaryServer::ReportSensorSysEvent(CallingContext &context, int32_t type, bool enable)
{
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    std::string packageName;
    manager_.GetPackageName(context.tokenId, packageName);
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        std::string(enable ? "Subscribe" : "Unsubscribe"),
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "UID", context.uid,
        "PKGNAME", packageName,
        "TYPE", type);
    if (ret != 0) {
        FI_HILOGE("HiviewDFX write failed, error:%{public}d", ret);
    }
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
}

#ifdef MOTION_ENABLE
int32_t StationaryServer::SubscribeMotion(Type type, sptr<IRemoteDevStaCallback> callback)
{
    FI_HILOGD("Enter");
    std::lock_guard lockGrd(mtx_);
    int32_t ret = 0;
    if (motionCallback_ == nullptr) {
        FI_HILOGI("create motion callback and subscribe");
        auto event = [this, type](const Data &data) {
            this->NotifyMotionCallback(type, data);
        };
        motionCallback_ = new (std::nothrow) MotionCallback(event);
        ret = SubscribeCallback(MOTION_TYPE_MAP[type], motionCallback_);
        if (ret != RET_OK) {
            FI_HILOGE("subscribe motion failed, ret = %{public}d", ret);
            return ret;
        }
    }
    FI_HILOGI("motionCallback is not null, subscribe ok");
    auto iter = deviceStatusMotionCallbacks_.find(type);
    if (iter == deviceStatusMotionCallbacks_.end()) {
        deviceStatusMotionCallbacks_[type] = std::set<sptr<IRemoteDevStaCallback>, Cmp>();
    }
    deviceStatusMotionCallbacks_[type].insert(callback);
    auto object = callback->AsObject();
    object->AddDeathRecipient(devStaCBDeathRecipient_);
    if (motionCallback_ != nullptr && cacheData_.find(type) != cacheData_.end()) {
        callback->OnDeviceStatusChanged(cacheData_[type]);
    }
    return ret;
}

int32_t StationaryServer::UnsubscribeMotion(Type type, sptr<IRemoteDevStaCallback> callback)
{
    FI_HILOGI("Enter");
    std::lock_guard lockGrd(mtx_);
    int32_t ret = 0;
    auto iter = deviceStatusMotionCallbacks_.find(type);
    if (iter == deviceStatusMotionCallbacks_.end()) {
        FI_HILOGE("dont find callback set in callbacks, failed");
        return RET_ERR;
    }
    auto callbackIter = deviceStatusMotionCallbacks_[type].find(callback);
    if (callbackIter == deviceStatusMotionCallbacks_[type].end()) {
        FI_HILOGE("dont find callback in callback set, failed");
        return RET_ERR;
    }
    deviceStatusMotionCallbacks_[type].erase(callbackIter);
    auto object = callback->AsObject();
    object->RemoveDeathRecipient(devStaCBDeathRecipient_);
    if (deviceStatusMotionCallbacks_[type].size() == 0) {
        ret = UnsubscribeCallback(MOTION_TYPE_MAP[type], motionCallback_);
        motionCallback_ = nullptr;
        if (ret != RET_OK) {
            FI_HILOGE("unsubscribe motion failed, ret = %{public}d", ret);
            return ret;
        }
        FI_HILOGI("unsubscribe motion succ");
        auto cacheIter = cacheData_.find(type);
        if (cacheIter != cacheData_.end()) {
            cacheData_.erase(cacheIter);
            FI_HILOGI("cache data clear");
        }
    }
    return ret;
}

void StationaryServer::StationaryServerDeathRecipient(const wptr<IRemoteObject> &remote)
{
    FI_HILOGW("Enter recv death notice");
    sptr<IRemoteObject> client = remote.promote();
    if (client == nullptr) {
        FI_HILOGE("OnRemoteDied failed, client is nullptr");
        return;
    }
    sptr<IRemoteDevStaCallback> callback = iface_cast<IRemoteDevStaCallback>(client);
    if (callback == nullptr) {
        FI_HILOGE("OnRemoteDied failed, callback is nullptr");
        return;
    }
    std::vector<std::pair<Type, sptr<IRemoteDevStaCallback>>> delCallbacks;
    {
        std::lock_guard lockGrd(mtx_);
        for (auto &[type, set] : deviceStatusMotionCallbacks_) {
            for (auto &callbackInSet : set) {
                if (callbackInSet->AsObject() == callback->AsObject()) {
                    delCallbacks.push_back(std::make_pair(type, callbackInSet));
                }
            }
        }
    }
    for (auto &[delType, delCallback] : delCallbacks) {
        UnsubscribeMotion(delType, delCallback);
        FI_HILOGW("remote died, unsubscribe motion");
    }
}

void StationaryServer::NotifyMotionCallback(Type type, const Data &data)
{
    FI_HILOGI("Enter, type %{public}d, data.value %{public}d", type, data.value);
    std::lock_guard lockGrd(mtx_);
    cacheData_[type] = data;
    auto iter = deviceStatusMotionCallbacks_.find(type);
    if (iter == deviceStatusMotionCallbacks_.end()) {
        FI_HILOGW("callbacks is empty");
        return;
    }
    for (auto callback : iter->second) {
        callback->OnDeviceStatusChanged(data);
    }
}
#endif
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS