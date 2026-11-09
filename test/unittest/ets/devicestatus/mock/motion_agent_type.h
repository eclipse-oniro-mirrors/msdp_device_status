/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DEVICE_STATUS_TEST_MOTION_AGENT_TYPE_H
#define DEVICE_STATUS_TEST_MOTION_AGENT_TYPE_H

#include <cstdint>

namespace OHOS {
namespace Msdp {
// Only the fields consumed by ani_drop_event.cpp; no sensor algorithm is simulated.
struct MotionEvent {
    int32_t type {0};
    int32_t status {0};
};
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_TEST_MOTION_AGENT_TYPE_H
