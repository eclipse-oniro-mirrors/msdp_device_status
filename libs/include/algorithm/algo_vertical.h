/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ALGO_VERTICAL_H
#define ALGO_VERTICAL_H

#include "algo_base.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class AlgoVertical : public AlgoBase {
public:
    explicit AlgoVertical(const std::shared_ptr<SensorDataCallback> sensorCallback) : AlgoBase(sensorCallback) {};
    virtual ~AlgoVertical() = default;
    bool Init(Type type) override;

private:
    bool StartAlgorithm(int32_t sensorTypeId, AccelData* sensorData) override;
    void ExecuteOperation() override;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ALGO_VERTICAL_H