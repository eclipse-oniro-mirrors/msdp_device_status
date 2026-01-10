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
 
#ifndef INTENTION_SERVICE_NEW_TEST_H
#define INTENTION_SERVICE_NEW_TEST_H
 
#include <gtest/gtest.h>
#include "nocopyable.h"
 
#include "delegate_tasks.h"
#include "device_manager.h"
#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "devicestatus_delayed_sp_singleton.h"
#include "drag_manager.h"
#include "i_context.h"
#include "timer_manager.h"
 
#include "intention_service.h"
#include "socket_session_manager.h"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class MockDelegateTasks : public IDelegateTasks {
public:
    int32_t PostSyncTask(DTaskCallback callback) override;
    int32_t PostAsyncTask(DTaskCallback callback) override;
};
 
class ContextService final : public IContext {
public:
    ContextService();
    ~ContextService() = default;
    DISALLOW_COPY_AND_MOVE(ContextService);
 
    IDelegateTasks& GetDelegateTasks() override;
    IDeviceManager& GetDeviceManager() override;
    ITimerManager& GetTimerManager() override;
    IDragManager& GetDragManager() override;
    IDDMAdapter& GetDDM() override;
    IPluginManager& GetPluginManager() override;
    ISocketSessionManager& GetSocketSessionManager() override;
    IInputAdapter& GetInput() override;
    IDSoftbusAdapter& GetDSoftbus() override;
    static ContextService* GetInstance();
private:
    MockDelegateTasks delegateTasks_;
    DeviceManager devMgr_;
    TimerManager timerMgr_;
    DragManager dragMgr_;
    SocketSessionManager socketSessionMgr_;
    std::unique_ptr<IDDMAdapter> ddm_ { nullptr };
    std::unique_ptr<IInputAdapter> input_ { nullptr };
    std::unique_ptr<IPluginManager> pluginMgr_ { nullptr };
    std::unique_ptr<IDSoftbusAdapter> dsoftbus_ { nullptr };
    sptr<IntentionService> intention_ { nullptr };
};
 
class IntentionServiceNewTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    static std::optional<DragData> CreateDragData(int32_t sourceType, int32_t pointerId, int32_t dragNum,
        bool hasCoordinateCorrected, int32_t shadowNum);
    void AssignToAnimation(PreviewAnimation &animation);

private:
    std::shared_ptr<IntentionService> intentionService_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_SERVICE_NEW_TEST_H