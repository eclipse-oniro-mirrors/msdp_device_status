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

#include "devicestatus_client.h"

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>

#include "iremote_broker.h"
#include "iremote_object.h"

#include "include/util.h"

#include "coordination_manager_impl.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"
#ifdef OHOS_BUILD_ENABLE_RUST_IMPL
#include "fusion_data_binding_internal.h"
#include "fusion_frameworks_binding.h"
#endif // OHOS_BUILD_ENABLE_RUST_IMPL

#undef LOG_TAG
#define LOG_TAG "DeviceStatusClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

DeviceStatusClient::DeviceStatusClient() {}
DeviceStatusClient::~DeviceStatusClient()
{
    if (devicestatusProxy_ != nullptr) {
        auto remoteObject = devicestatusProxy_->AsObject();
        if (remoteObject != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

ErrCode DeviceStatusClient::Connect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (devicestatusProxy_ != nullptr) {
        return RET_OK;
    }

    sptr<ISystemAbilityManager> sa = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPR(sa, E_DEVICESTATUS_GET_SYSTEM_ABILITY_MANAGER_FAILED);

    sptr<IRemoteObject> remoteObject = sa->CheckSystemAbility(MSDP_DEVICESTATUS_SERVICE_ID);
    CHKPR(remoteObject, E_DEVICESTATUS_GET_SERVICE_FAILED);

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) DeviceStatusDeathRecipient());
    CHKPR(deathRecipient_, ERR_NO_MEMORY);

    if (remoteObject->IsProxyObject()) {
        if (!remoteObject->AddDeathRecipient(deathRecipient_)) {
            FI_HILOGE("Add death recipient to DeviceStatus service failed");
            return E_DEVICESTATUS_ADD_DEATH_RECIPIENT_FAILED;
        }
    }

    devicestatusProxy_ = iface_cast<Idevicestatus>(remoteObject);
    FI_HILOGD("Connecting DeviceStatusService success");
    return RET_OK;
}

void DeviceStatusClient::ResetProxy(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHKPV(devicestatusProxy_);
    auto serviceRemote = devicestatusProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        devicestatusProxy_ = nullptr;
    }
    if (deathListener_ != nullptr) {
        FI_HILOGI("Notify service death to listener");
        deathListener_();
    }
}

void DeviceStatusClient::DeviceStatusDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    CHKPV(remote);
    DeviceStatusClient::GetInstance().ResetProxy(remote);
    FI_HILOGD("Recv death notice");
}

#ifdef OHOS_BUILD_ENABLE_RUST_IMPL

int32_t DeviceStatusClient::AllocSocketPair(int32_t moduleType)
{
    const std::string programName(GetProgramName());
    int32_t ret = fusion_alloc_socket_fd(programName.c_str(), moduleType, &socketFd_, &tokenType_);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to connect to server via socket:%{public}d", ret);
        return RET_ERR;
    }
    FI_HILOGI("Connected successfully to server via socket, "
        "socketFd_:%{public}d tokenType_:%{public}d",
        socketFd_, tokenType_);
    return RET_OK;
}

#else // OHOS_BUILD_ENABLE_RUST_IMPL

int32_t DeviceStatusClient::AllocSocketPair(int32_t moduleType)
{
    CALL_DEBUG_ENTER;
    DEV_RET_IF_NULL_WITH_RET((Connect() != RET_OK), RET_ERR);
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPR(devicestatusProxy_, RET_ERR);
    const std::string programName(GetProgramName());
    int32_t result = devicestatusProxy_->AllocSocketFd(programName, moduleType, socketFd_, tokenType_);
    if (result != RET_OK) {
        FI_HILOGE("AllocSocketFd has error:%{public}d", result);
        return RET_ERR;
    }

    FI_HILOGI("AllocSocketPair success, socketFd_:%{public}d, tokenType_:%{public}d", socketFd_, tokenType_);
    return RET_OK;
}

#endif // OHOS_BUILD_ENABLE_RUST_IMPL

int32_t DeviceStatusClient::GetClientSocketFdOfAllocedSocketPair() const
{
    CALL_DEBUG_ENTER;
    return socketFd_;
}

void DeviceStatusClient::RegisterDeathListener(std::function<void()> deathListener)
{
    deathListener_ = deathListener;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
