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

#ifndef DISTANCE_MEASUREMENT_CALLBACK_H
#define DISTANCE_MEASUREMENT_CALLBACK_H

#include "distance_measurement_event_napi.h"

namespace OHOS {
namespace Msdp {
using CDistMeasureResponse = DistanceMeasurementEventNapi::CDistMeasureResponse;
using CDoorPositionResponse = DistanceMeasurementEventNapi::CDoorPositionResponse;

class IDistanceMeasurementListener {
public:
    IDistanceMeasurementListener() = default;
    virtual ~IDistanceMeasurementListener() = default;
    virtual void OnDistanceMeasurementChanged(const CDistMeasureResponse &distMeasureRes) const = 0;
    virtual void OnDoorIdentifyChanged(const CDoorPositionResponse &indentifyRes) const = 0;
    virtual void UpdateEnv(const napi_env &env) = 0;
};
} // namespace Msdp
} // namespace OHOS
#endif // DISTANCE_MEASUREMENT_CALLBACK_H