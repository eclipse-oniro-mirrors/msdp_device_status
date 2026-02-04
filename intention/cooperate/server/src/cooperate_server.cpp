/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "cooperate_server.h"

#include <chrono>

#include <tokenid_kit.h>

#include "accesstoken_kit.h"
#include "devicestatus_define.h"
#include "ipc_skeleton.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "CooperateServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t DEFAULT_UNLOAD_COOLING_TIME_MS { 60000 };
}

CooperateServer::CooperateServer(IContext *context)
    : context_(context)
{
    (void) context_;
    (void) unloadTimerId_;
}

int32_t CooperateServer::EnableCooperate(CallingContext &context, int32_t userData)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    if (unloadTimerId_ >= 0) {
        context_->GetTimerManager().RemoveTimer(unloadTimerId_);
    }
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    cooperate->Enable(context.tokenId, context.pid, userData);
    return RET_OK;
}

int32_t CooperateServer::DisableCooperate(CallingContext &context, int32_t userData)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    cooperate->Disable(context.pid, userData);
    unloadTimerId_ = context_->GetTimerManager().AddTimer(DEFAULT_UNLOAD_COOLING_TIME_MS, REPEAT_ONCE,
        []() {
            FI_HILOGI("Unload \'cooperate\' module");
        });
    if (unloadTimerId_ < 0) {
        FI_HILOGE("AddTimer failed, will not unload Cooperate");
    }
    return RET_OK;
}

int32_t CooperateServer::StartCooperate(CallingContext &context, const std::string& remoteNetworkId,
    int32_t userData, int32_t startDeviceId, bool checkPermission)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->Start(context.pid, userData, remoteNetworkId, startDeviceId, context.uid);
}

int32_t CooperateServer::StartCooperateWithOptions(CallingContext &context, const std::string& remoteNetworkId,
    int32_t userData, int32_t startDeviceId, CooperateOptions options)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->StartWithOptions(context.pid, userData, remoteNetworkId, startDeviceId, options);
}

int32_t CooperateServer::StopCooperate(CallingContext &context, int32_t userData, bool isUnchained,
    bool checkPermission)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->Stop(context.pid, userData, isUnchained);
}

int32_t CooperateServer::RegisterCooperateListener(CallingContext &context)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->RegisterListener(context.pid);
}

int32_t CooperateServer::UnregisterCooperateListener(CallingContext &context)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->UnregisterListener(context.pid);
}

int32_t CooperateServer::RegisterHotAreaListener(CallingContext &context, int32_t userData, bool checkPermission)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->RegisterHotAreaListener(context.pid);
}

int32_t CooperateServer::UnregisterHotAreaListener(CallingContext &context)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->UnregisterHotAreaListener(context.pid);
}

int32_t CooperateServer::RegisterMouseEventListener(CallingContext &context, const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->RegisterEventListener(context.pid, networkId);
}

int32_t CooperateServer::UnregisterMouseEventListener(CallingContext &context, const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->UnregisterEventListener(context.pid, networkId);
}

int32_t CooperateServer::GetCooperateStateSync(CallingContext &context, const std::string &udid, bool &state)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    if (cooperate->GetCooperateState(udid, state) != RET_OK) {
        FI_HILOGE("GetCooperateState failed");
        return RET_ERR;
    }
    FI_HILOGI("GetCooperateState for udId:%{public}s successfully, state:%{public}s",
        Utility::Anonymize(udid).c_str(), state ? "true" : "false");
    return RET_OK;
}

int32_t CooperateServer::GetCooperateStateAsync(CallingContext &context, const std::string &networkId,
    int32_t userData, bool isCheckPermission)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->GetCooperateState(context.pid, userData, networkId);
}

int32_t CooperateServer::SetDamplingCoefficient(CallingContext &context, uint32_t direction, double coefficient)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    FI_HILOGI("SetDamplingCoefficient(0x%{public}x, %{public}.3f)", direction, coefficient);
    return cooperate->SetDamplingCoefficient(direction, coefficient);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
