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
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "StationaryClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t StationaryClient::SubscribeCallback(Type type, ActivityEvent event,
    ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback)
{
    int32_t ret = INTENTION_CLIENT->SubscribeStationaryCallback(type, event, latency, callback);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeStationary fail, ret:%{public}d", ret);
    }
    std::lock_guard lockGrd(mtx_);
    auto iter = std::find_if(subParams_.begin(), subParams_.end(),
        [type, event, latency, callback](const SubscribeStationaryParam &param) {
            return param.type_ == type && param.event_ == event && param.latency_ == latency &&
                param.callback_ == callback;
        });
    if (iter == subParams_.end()) {
        subParams_.emplace_back(type, event, latency, callback);
        FI_HILOGI("insert callback in subParams, type = %{public}d, size = %{public}zu", type, subParams_.size());
    }
    return ret;
}

int32_t StationaryClient::UnsubscribeCallback(Type type, ActivityEvent event,
    sptr<IRemoteDevStaCallback> callback)
{
    int32_t ret =
        INTENTION_CLIENT->UnsubscribeStationaryCallback(type, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeStationary fail, ret:%{public}d", ret);
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

Data StationaryClient::GetDeviceStatusData(Type type)
{
    Data reply;
    int32_t replyType = -1;
    int32_t replyValue = -1;
    int32_t ret = INTENTION_CLIENT->GetDeviceStatusData(type, replyType, replyValue);
    if (ret != RET_OK) {
        FI_HILOGE("GetDeviceStatusData fail, ret:%{public}d", ret);
    }
    reply.type = static_cast<Type>(replyType);
    reply.value = static_cast<OnChangedValue>(replyValue);
    return reply;
}

void StationaryClient::OnConnected()
{
    std::lock_guard lockGrd(mtx_);
    if (subParams_.empty()) {
        FI_HILOGI("subParams is empty");
        return;
    }
    int32_t ret = RET_OK;
    FI_HILOGI("subParams size = %{public}zu", subParams_.size());
    for (const auto &param : subParams_) {
        ret = INTENTION_CLIENT->SubscribeStationaryCallback(param.type_, param.event_, param.latency_,
            param.callback_);
        if (ret != RET_OK) {
            FI_HILOGE("ResubscribeStationary fail, ret = %{public}d", ret);
        }
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
