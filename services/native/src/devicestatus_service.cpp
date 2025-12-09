/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "devicestatus_service.h"

#include <unistd.h>
#include <vector>

#include <ipc_skeleton.h>
#ifdef MSDP_HIVIEWDFX_HITRACE_ENABLE
#include <hitrace_meter.h>
#endif // MSDP_HIVIEWDFX_HITRACE_ENABLE
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include <hisysevent.h>
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#ifdef MEMMGR_ENABLE
#include <mem_mgr_client.h>
#endif // MEMMGR_ENABLE
#include <system_ability_definition.h>

#include "concurrent_task_client.h"
#include "ddm_adapter.h"
#include "devicestatus_common.h"
#ifdef MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include "devicestatus_hisysevent.h"
#endif // MSDP_HIVIEWDFX_HISYSEVENT_ENABLE
#include "dsoftbus_adapter.h"
#include "input_adapter.h"
#include "plugin_manager.h"
#include "qos.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusService"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t DEFAULT_WAIT_TIME_MS { 1000 };
constexpr int32_t WAIT_FOR_ONCE { 1 };
constexpr int32_t MAX_N_RETRIES { 100 };

struct device_status_epoll_event {
    int32_t fd { 0 };
    EpollEventType event_type { EPOLL_EVENT_BEGIN };
};

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSpSingleton<DeviceStatusService>::GetInstance().GetRefPtr());
} // namespace

DeviceStatusService::DeviceStatusService()
    : SystemAbility(MSDP_DEVICESTATUS_SERVICE_ID, true)
{
    ddm_ = std::make_unique<DDMAdapter>();
    input_ = std::make_unique<InputAdapter>();
    pluginMgr_ = std::make_unique<PluginManager>(this);
    dsoftbus_ = std::make_unique<DSoftbusAdapter>();
}

DeviceStatusService::~DeviceStatusService()
{}

void DeviceStatusService::OnDump()
{}

void DeviceStatusService::OnAddSystemAbility(int32_t saId, const std::string &deviceId)
{
    FI_HILOGI("OnAddSystemAbility systemAbilityId:%{public}d added!", saId);
#ifdef MEMMGR_ENABLE
    if (saId == MEMORY_MANAGER_SA_ID) {
        Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), PROCESS_TYPE_SA, PROCESS_STATUS_STARTED,
            MSDP_DEVICESTATUS_SERVICE_ID);
    }
#endif
}

void DeviceStatusService::OnStart()
{
    CALL_INFO_TRACE;
    if (ready_) {
        FI_HILOGE("On start is ready, nothing to do");
        return;
    }

    uint64_t tid = GetThisThreadId();
    delegateTasks_.SetWorkerThreadId(tid);

    if (!Init()) {
        FI_HILOGE("On start call init failed");
        return;
    }
#ifdef MEMMGR_ENABLE
    AddSystemAbilityListener(MEMORY_MANAGER_SA_ID);
#endif
    EnableDSoftbus();
    EnableDDM();
    FI_HILOGI("check live start intention");
    intention_ = sptr<IntentionService>::MakeSptr(this);
    if (!Publish(intention_)) {
        FI_HILOGE("On start register to system ability manager failed");
        return;
    }
    intention_->ListenLiveBroadcast();
    state_ = ServiceRunningState::STATE_RUNNING;
    ready_ = true;
    worker_ = std::thread([this] { this->OnThread(); });
}

void DeviceStatusService::OnStop()
{
    CALL_INFO_TRACE;
    if (!ready_) {
        return;
    }
    ready_ = false;
    state_ = ServiceRunningState::STATE_EXIT;

    delegateTasks_.PostAsyncTask([]() -> int32_t {
        FI_HILOGD("No op");
        return RET_OK;
    });
    if (worker_.joinable()) {
        worker_.join();
    }
#ifdef MEMMGR_ENABLE
    Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), PROCESS_TYPE_SA, PROCESS_STATUS_DIED,
        MSDP_DEVICESTATUS_SERVICE_ID);
#endif
}

IDelegateTasks& DeviceStatusService::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& DeviceStatusService::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& DeviceStatusService::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& DeviceStatusService::GetDragManager()
{
    return dragMgr_;
}

ISocketSessionManager& DeviceStatusService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IDDMAdapter& DeviceStatusService::GetDDM()
{
    return *ddm_;
}

IPluginManager& DeviceStatusService::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& DeviceStatusService::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& DeviceStatusService::GetDSoftbus()
{
    return *dsoftbus_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
