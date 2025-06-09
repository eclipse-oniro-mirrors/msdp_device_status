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

#ifndef STATIONARY_DATA_H
#define STATIONARY_DATA_H

#include <string>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr double MOVEMENT_THRESHOLD { 0.001 };
enum Type {
    TYPE_INVALID = -1,
    TYPE_ABSOLUTE_STILL,
    TYPE_HORIZONTAL_POSITION,
    TYPE_VERTICAL_POSITION,
    TYPE_STILL,
    TYPE_RELATIVE_STILL,
    TYPE_CAR_BLUETOOTH,
    TYPE_LID_OPEN,
    TYPE_STAND,
    TYPE_MAX
};

enum TypeValue : bool {
    INVALID = false,
    VALID = true
};

enum OnChangedValue {
    VALUE_INVALID = -1,
    VALUE_ENTER = 1,
    VALUE_EXIT = 2
};

enum ActivityEvent {
    EVENT_INVALID = 0,
    ENTER = 1,
    EXIT = 2,
    ENTER_EXIT = 3
};

enum ReportLatencyNs {
    Latency_INVALID = -1,
    SHORT = 1,
    MIDDLE = 2,
    LONG = 3
};
enum Status {
    STATUS_INVALID = -1,
    STATUS_CANCEL,
    STATUS_START,
    STATUS_PROCESS,
    STATUS_FINISH
};

enum Action {
    ACTION_INVALID = -1,
    ACTION_ENLARGE,
    ACTION_REDUCE,
    ACTION_UP,
    ACTION_LEFT,
    ACTION_DOWN,
    ACTION_RIGHT
};

struct Data {
    Type type { TYPE_INVALID };
    OnChangedValue value { VALUE_INVALID };
    Status status { STATUS_INVALID };
    Action action { ACTION_INVALID };
    double movement { 0.0 };

    bool operator !=(const Data &r) const
    {
        if (type == r.type && value == r.value &&
            status - r.status && action == r.action && (movement - r.movement) < MOVEMENT_THRESHOLD) {
            return false;
        }
        return true;
    }
};

struct DevicePostureData {
    float rollRad = 0.0F;
    float pitchRad = 0.0F;
    float yawRad = 0.0F;
};

typedef struct DeviceStatusJsonData {
    int32_t type { -1 };
    std::string json;
}DeviceStatusJsonD;

static DeviceStatusJsonD DeviceStatusJson[] = {
    { Type::TYPE_ABSOLUTE_STILL, "absoluteStill" },
    { Type::TYPE_HORIZONTAL_POSITION, "horizontalPosition" },
    { Type::TYPE_VERTICAL_POSITION, "verticalPosition" },
    { Type::TYPE_STILL, "still" },
    { Type::TYPE_RELATIVE_STILL, "relativeStill" },
    { Type::TYPE_CAR_BLUETOOTH, "carBluetooth" },
    { Type::TYPE_LID_OPEN, "LID_OPEN" },
    { Type::TYPE_MAX, "MAX" }
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // STATIONARY_DATA_H
