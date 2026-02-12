/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_SERVICE_H
#define DEVICESTATUS_SERVICE_H

#include <memory>

#include <iremote_object.h>
#include <system_ability.h>

#include "delegate_tasks.h"
#include "device_manager.h"
#include "devicestatus_delayed_sp_singleton.h"
#include "devicestatus_dumper.h"
#include "devicestatus_manager.h"
#include "devicestatus_srv_stub.h"
#include "drag_data.h"
#include "drag_manager.h"
#include "i_context.h"
#include "intention_service.h"
#include "iremote_dev_sta_callback.h"
#include "socket_session_manager.h"
#include "stationary_data.h"
#include "stream_server.h"
#include "timer_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum class ServiceRunningState {STATE_NOT_START, STATE_RUNNING, STATE_EXIT};
class DeviceStatusService final : public IContext,
                                  public StreamServer,
                                  public SystemAbility,
                                  public DeviceStatusSrvStub {
    DECLARE_SYSTEM_ABILITY(DeviceStatusService)
    DECLARE_DELAYED_SP_SINGLETON(DeviceStatusService);
public:
    virtual void OnDump() override;
    virtual void OnStart() override;
    virtual void OnStop() override;

    IDelegateTasks& GetDelegateTasks() override;
    IDeviceManager& GetDeviceManager() override;
    ITimerManager& GetTimerManager() override;
    IDragManager& GetDragManager() override;

    IDDMAdapter& GetDDM() override;
    IPluginManager& GetPluginManager() override;
    ISocketSessionManager& GetSocketSessionManager() override;
    IInputAdapter& GetInput() override;
    IDSoftbusAdapter& GetDSoftbus() override;

    void OnAddSystemAbility(int32_t saId, const std::string &deviceId) override;
    void Subscribe(Type type, ActivityEvent event, ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback) override;
    void Unsubscribe(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback) override;
    Data GetCache(const Type &type) override;
    bool IsServiceReady() const;
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override;
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
    void ReportSensorSysEvent(int32_t type, bool enable);
#endif
    int32_t AllocSocketFd(const std::string &programName, int32_t moduleType,
    int32_t &toReturnClientFd, int32_t &tokenType) override;
    void OnConnected(SessionPtr s) override;
    void OnDisconnected(SessionPtr s) override;
    int32_t AddEpoll(EpollEventType type, int32_t fd) override;
    int32_t DelEpoll(EpollEventType type, int32_t fd);
    bool IsRunning() const override;

private:
    bool Init();
    int32_t InitDelegateTasks();
    int32_t InitTimerMgr();
    void OnThread();
    void OnSocketEvent(const struct epoll_event &ev);
    void OnDelegateTask(const epoll_event &ev);
    void OnTimeout(const epoll_event &ev);
    void OnDeviceMgr(const epoll_event &ev);
    int32_t EnableSocketSessionMgr(int32_t nRetries);
    int32_t EnableDevMgr(int32_t nRetries);
    void EnableDSoftbus(int32_t nRetries);
    void EnableDDM(int32_t nRetries);

private:
    std::atomic<ServiceRunningState> state_ { ServiceRunningState::STATE_NOT_START };
    std::thread worker_;
    DelegateTasks delegateTasks_;
    DeviceManager devMgr_;
    TimerManager timerMgr_;
    std::atomic<bool> ready_ { false };
    std::shared_ptr<DeviceStatusManager> devicestatusManager_ { nullptr };
    DragManager dragMgr_;
    SocketSessionManager socketSessionMgr_;
    std::unique_ptr<IDDMAdapter> ddm_;
    std::unique_ptr<IInputAdapter> input_;
    std::unique_ptr<IPluginManager> pluginMgr_;
    std::unique_ptr<IDSoftbusAdapter> dsoftbus_;
    sptr<IntentionService> intention_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_SERVICE_H
