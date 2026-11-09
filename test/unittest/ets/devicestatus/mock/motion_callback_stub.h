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

#ifndef DEVICE_STATUS_TEST_MOTION_CALLBACK_STUB_H
#define DEVICE_STATUS_TEST_MOTION_CALLBACK_STUB_H

#include "refbase.h"
#include "motion_agent_type.h"

namespace OHOS {
namespace Msdp {
// IPC transport is replaced; AniMotionCallback's production forwarding code is retained.
class IMotionCallback : public RefBase {
public:
    virtual void OnMotionChanged(const MotionEvent &event) = 0;
    ~IMotionCallback() override = default;
};

class MotionCallbackStub : public IMotionCallback {
public:
    ~MotionCallbackStub() override = default;
};
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_TEST_MOTION_CALLBACK_STUB_H
