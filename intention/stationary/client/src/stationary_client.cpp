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

#include "stationary_client.h"

#include "default_params.h"
#include "devicestatus_define.h"
#include "stationary_params.h"

#undef LOG_TAG
#define LOG_TAG "StationaryClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t StationaryClient::SubscribeCallback(ITunnelClient &tunnel, Type type, ActivityEvent event,
    ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback)
{
    SubscribeStationaryParam param { type, event, latency, callback };
    DefaultReply reply {};
    FI_HILOGI("SubscribeStationary(type:%{public}d,event:%{public}d,latency:%{public}d)", type, event, latency);
    int32_t ret = tunnel.AddWatch(Intention::STATIONARY, StationaryRequestID::SUBSCRIBE_STATIONARY, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeStationary fail, error:%{public}d", ret);
    }
    std::lock_guard lockGrd(mtx_);
    auto iter = std::find_if(subParams_.begin(), subParams_.end(),
        [type, event, latency, callback](const SubscribeStationaryParam &param) {
            return param.type_ == type && param.event_ == event && param.callback_ == callback;
        });
    if (iter == subParams_.end()) {
        subParams_.emplace_back(type, event, latency, callback);
        FI_HILOGI("insert callback in subParams, type = %{public}d, size = %{public}zu", type, subParams_.size());
    }
    return ret;
}

int32_t StationaryClient::UnsubscribeCallback(ITunnelClient &tunnel, Type type, ActivityEvent event,
    sptr<IRemoteDevStaCallback> callback)
{
    UnsubscribeStationaryParam param { type, event, ReportLatencyNs::Latency_INVALID, callback };
    DefaultReply reply {};
    FI_HILOGI("UnsubscribeStationary(type:%{public}d,event:%{public}d)", type, event);
    int32_t ret = tunnel.RemoveWatch(Intention::STATIONARY, StationaryRequestID::UNSUBSCRIBE_STATIONARY, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeStationary fail, error:%{public}d", ret);
    }
    std::lock_guard lockGrd(mtx_);
    auto iter = std::find_if(subParams_.begin(), subParams_.end(),
        [type, event, callback](const SubscribeStationaryParam &param) {
            return param.type_ == type && param.event_ == event && param.callback_ == callback;
        });
    if (iter != subParams_.end()) {
        subParams_.erase(iter);
        FI_HILOGI("delete callback in subParams, type = %{public}d, size = %{public}zu", type, subParams_.size());
    }
    return ret;
}

Data StationaryClient::GetDeviceStatusData(ITunnelClient &tunnel, Type type)
{
    GetStaionaryDataParam param { type };
    GetStaionaryDataReply reply {};
    FI_HILOGI("GetDeviceStatusData(type:%{public}d)", type);
    int32_t ret = tunnel.GetParam(Intention::STATIONARY, StationaryRequestID::GET_STATIONARY_DATA, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("GetStationaryData fail, error:%{public}d", ret);
    }
    return reply.data_;
}

void StationaryClient::OnConnected(ITunnelClient &tunnel)
{
    std::lock_guard lockGrd(mtx_);
    if (subParams_.empty()) {
        FI_HILOGI("subParams is empty");
        return;
    }
    int32_t ret = RET_OK;
    DefaultReply reply {};
    FI_HILOGI("subParams size = %{public}zu", subParams_.size());
    for (auto &param : subParams_) {
        ret = tunnel.AddWatch(Intention::STATIONARY, StationaryRequestID::SUBSCRIBE_STATIONARY, param, reply);
        if (ret != RET_OK) {
            FI_HILOGE("ResubscribeStationary fail, ret = %{public}d", ret);
        }
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
