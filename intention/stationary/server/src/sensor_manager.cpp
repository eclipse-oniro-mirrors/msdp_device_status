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

#include "sensor_manager.h"

#include <securec.h>

#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t RET_ERR = -1;
constexpr int32_t RET_OK = 0;
}

SensorManager::SensorManager(const int32_t sensorTypeId, const int32_t sensorSamplingInterval,
    RecordSensorCallback callback)
{
    sensorTypeId_ = sensorTypeId;
    sensorSamplingInterval_ = sensorSamplingInterval;
    sensorUser_.callback = callback;
    (void)memset_s(sensorUser_.name, sizeof(sensorUser_.name), 0, sizeof(sensorUser_.name));
    sensorUser_.plugCallback = nullptr;
    isRunning_ = false;
}

SensorManager::~SensorManager()
{
    StopSensor();
}

int32_t SensorManager::StartSensor()
{
    std::lock_guard lockGrd(mtx_);
    if (isRunning_ == true) {
        FI_HILOGE("sensor manager is running");
        return RET_OK;
    }
    if (sensorUser_.callback == nullptr) {
        FI_HILOGI("sensorUser callback is nullptr");
        return RET_ERR;
    }
    int32_t ret = SubscribeSensor(sensorTypeId_, &sensorUser_);
    if (ret != 0) {
        FI_HILOGE("Subscribe sensor failed, ret = %{public}d", ret);
        return ret;
    }
    ret = SetBatch(sensorTypeId_, &sensorUser_, sensorSamplingInterval_, 0);
    if (ret != 0) {
        FI_HILOGE("Set Batch failed, ret = %{public}d", ret);
        UnsubscribeSensor(sensorTypeId_, &sensorUser_);
        return ret;
    }
    ret = ActivateSensor(sensorTypeId_, &sensorUser_);
    if (ret != 0) {
        FI_HILOGE("Activate sensor failed, ret = %{public}d", ret);
        UnsubscribeSensor(sensorTypeId_, &sensorUser_);
        return ret;
    }
    isRunning_ = true;
    return ret;
}

int32_t SensorManager::StopSensor()
{
    std::lock_guard lockGrd(mtx_);
    if (isRunning_ == false) {
        FI_HILOGE("sensor manager is stopped");
        return RET_OK;
    }
    int32_t ret = DeactivateSensor(sensorTypeId_, &sensorUser_);
    if (ret != 0) {
        FI_HILOGE("Activate sensor failed, ret %{public}d", ret);
    }
    ret = UnsubscribeSensor(sensorTypeId_, &sensorUser_);
    if (ret != 0) {
        FI_HILOGE("Unsubscribe sensor failed, ret %{public}d", ret);
    }
    isRunning_ = false;
    return ret;
}

bool SensorManager::IsSupportedSensor(const int32_t sensorTypeId)
{
    SensorInfo *sensorInfos { nullptr };
    int32_t count { 0 };
    int32_t ret = GetAllSensors(&sensorInfos, &count);
    if (ret != 0) {
        FI_HILOGE("Failed to get all sensors");
        return false;
    }
    for (int32_t i = 0; i < count; i++) {
        if (sensorTypeId == sensorInfos[i].sensorTypeId) {
            return true;
        }
    }
    return false;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS