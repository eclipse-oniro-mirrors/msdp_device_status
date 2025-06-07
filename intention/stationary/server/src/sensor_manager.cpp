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

#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
SensorManager::SensorManager(const int32_t sensorTypeId, const int32_t sensorSamplingInterval)
{
    sensorTypeId_ = sensorTypeId;
    sensorSamplingInterval_ = sensorSamplingInterval;
    isRunning_ = false;
}

SensorManager::~SensorManager()
{
    StopSensor();
}

void SensorManager::SetCallback(RecordSensorCallback callback)
{
    sensorUser_.callback = callback;
}

int32_t SensorManager::StartSensor()
{
    int32_t ret = SubscribeSensor(sensorTypeId_, &sensorUser_);
    if (ret != 0) {
        FI_HILOGE("Subscribe sensor failed, ret = %{public}d", ret);
        return ret;
    }
    ret = SetBatch(sensorTypeId_, &sensorUser_, sensorSamplingInterval_, 0);
    if (ret != 0) {
        FI_HILOGE("Set Batch failed, ret = %{public}d", ret);
        return ret;
    }
    ret = ActivateSensor(sensorTypeId_, &sensorUser_);
    if (ret != 0) {
        FI_HILOGE("Activate sensor failed, ret = %{public}d", ret);
        return ret;
    }
    isRunning_ = true;
    return ret;
}

int32_t SensorManager::StopSensor()
{
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

bool SensorManager::GetRunningStatus()
{
    return isRunning_.load();
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