/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef COOPERATE_CONTEXT_TEST_H
#define COOPERATE_CONTEXT_TEST_H

#include <gtest/gtest.h>

#include <fcntl.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "cooperate_events.h"
#include "delegate_tasks.h"
#include "device_manager.h"
#include "devicestatus_define.h"
#include "devicestatus_delayed_sp_singleton.h"
#include "drag_manager.h"
#include "i_context.h"
#include "test_context.h"
#include "timer_manager.h"

#include "intention_service.h"
#include "socket_session_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CooperateContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    void SetIContext(IContext *context);
    void OnThreeStates(const Cooperate::CooperateEvent &event);
private:
    std::shared_ptr<TestContext> context_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_CONTEXT_TEST_H