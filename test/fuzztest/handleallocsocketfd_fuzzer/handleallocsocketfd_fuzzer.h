/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef HANDLEALLOCSOCKETFD_FUZZER_H
#define HANDLEALLOCSOCKETFD_FUZZER_H

#define FUZZ_PROJECT_NAME "handleallocsocketfd_fuzzer"

#include <memory>
#include <string>

#include <fcntl.h>
#include "nocopyable.h"

#include "cooperate_events.h"
#include "delegate_tasks.h"
#include "device_manager.h"
#include "devicestatus_define.h"
#include "devicestatus_delayed_sp_singleton.h"
#include "drag_manager.h"
#include "i_context.h"
#include "timer_manager.h"
#define private public
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"
#include "ddm_adapter.h"
#include "devicestatus_define.h"

#include "intention_service.h"
#include "socket_session_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

struct TimerInfo {
    int32_t times { 0 };
    int32_t timerId { 0 };
};

class ContextService final : public IContext {
    ContextService();
    ~ContextService();
    DISALLOW_COPY_AND_MOVE(ContextService);
public:
    IDelegateTasks& GetDelegateTasks() override;
    IDeviceManager& GetDeviceManager() override;
    ITimerManager& GetTimerManager() override;
    IDragManager& GetDragManager() override;
    IDDMAdapter& GetDDM() override;
    IPluginManager& GetPluginManager() override;
    ISocketSessionManager& GetSocketSessionManager() override;
    IInputAdapter& GetInput() override;
    IDSoftbusAdapter& GetDSoftbus() override;
private:
    void OnStart();
    void OnStop();
    bool Init();
    int32_t EpollCreate();
    int32_t AddEpoll(EpollEventType type, int32_t fd);
    int32_t DelEpoll(EpollEventType type, int32_t fd);
    int32_t EpollCtl(int32_t fd, int32_t op, struct epoll_event &event);
    int32_t EpollWait(int32_t maxevents, int32_t timeout, struct epoll_event &events);
    void EpollClose();
    int32_t InitTimerMgr();
    int32_t InitDevMgr();
    void OnThread();
    void OnTimeout(const epoll_event &ev);
    void OnDeviceMgr(const epoll_event &ev);
    int32_t EnableDevMgr(int32_t nRetries);
    void DisableDevMgr();
    int32_t InitDelegateTasks();
    void OnDelegateTask(const struct epoll_event &ev);
    static ContextService* GetInstance();
private:
    std::atomic<ServiceRunningState> state_ { ServiceRunningState::STATE_NOT_START };
    std::thread worker_;
    DelegateTasks delegateTasks_;
    DeviceManager devMgr_;
    TimerManager timerMgr_;
    std::atomic<bool> ready_ { false };
    DragManager dragMgr_;
    int32_t epollFd_ { -1 };
    SocketSessionManager socketSessionMgr_;
    std::unique_ptr<IDDMAdapter> ddm_;
    std::unique_ptr<IInputAdapter> input_;
    std::unique_ptr<IPluginManager> pluginMgr_;
    std::unique_ptr<IDSoftbusAdapter> dsoftbusAda_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // HANDLEALLOCSOCKETFD_FUZZER_H