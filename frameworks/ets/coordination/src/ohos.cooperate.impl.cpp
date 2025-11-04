/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ohos.cooperate.proj.hpp"
#include "ohos.cooperate.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ets_cooperate_manager.h"
#include "devicestatus_errors.h"
#include "coordination_message.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "ohos.cooperate"

namespace {
using namespace OHOS::Msdp::DeviceStatus;
using namespace OHOS::Msdp;
void PrepareCooperateAsync(uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Prepare(true, opq, promise);
    return;
}

uintptr_t PrepareCooperatePromise()
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Prepare(true, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void UnprepareCooperateAsync(uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Prepare(false, opq, promise);
    return;
}

uintptr_t UnprepareCooperatePromise()
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Prepare(false, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void ActivateCooperateAsync(taihe::string_view targetNetworkId, int32_t inputDeviceId, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Activate(targetNetworkId.c_str(), inputDeviceId, opq, promise);
    return;
}

uintptr_t ActivateCooperatePromise(::taihe::string_view targetNetworkId, int32_t inputDeviceId)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Activate(targetNetworkId.c_str(), inputDeviceId, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void DeactivateCooperateAsync(bool isUnchained, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Deactivate(isUnchained, opq, promise);
    return;
}

uintptr_t DeactivateCooperatePromise(bool isUnchained)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->Deactivate(isUnchained, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void GetCooperateSwitchStateAsync(::taihe::string_view networkId, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->GetCrossingSwitchState(networkId.c_str(), opq, promise);
    return;
}

uintptr_t GetCooperateSwitchStatePromise(::taihe::string_view networkId)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    EtsCooperateManager::GetInstance()->GetCrossingSwitchState(networkId.c_str(), 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

uintptr_t ActivateCooperateWithOptionsPromise(::taihe::string_view targetNetworkId, int32_t inputDeviceId,
    taihe::optional_view<CooperateOptions_t> cooperateOptions)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    if (!cooperateOptions.has_value()) {
        FI_HILOGI("CooperateOptions is not assigned, call ActivateCooperate");
        EtsCooperateManager::GetInstance()->Activate(targetNetworkId.c_str(), inputDeviceId, 0, promise);
        return reinterpret_cast<uintptr_t>(promise);
    }
    EtsCooperateManager::GetInstance()->ActivateCooperateWithOptions(targetNetworkId.c_str(), inputDeviceId,
        cooperateOptions.value(), 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void OnCooperateMessageInner(::taihe::callback_view<void(CooperateMessage_t const&)> f, uintptr_t opq)
{
    EtsCooperateManager::GetInstance()->RegisterCooperateListener("cooperateMessage", f, opq);
}

void OffCooperateMessageInner(::taihe::optional_view<uintptr_t> opq)
{
    EtsCooperateManager::GetInstance()->UnRegisterCooperateListener("cooperateMessage", opq);
}

void OnCooperateMouseEventInner(::taihe::string_view networkId,
    ::taihe::callback_view<void(MouseLocation_t const&)> f, uintptr_t opq)
{
    EtsCooperateManager::GetInstance()->RegisterMouseListener(networkId.c_str(), f, opq);
}

void OffCooperateMouseEventInner(::taihe::string_view networkId, ::taihe::optional_view<uintptr_t> opq)
{
    EtsCooperateManager::GetInstance()->UnRegisterMouseListener(networkId.c_str(), opq);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_PrepareCooperateAsync(PrepareCooperateAsync);
TH_EXPORT_CPP_API_PrepareCooperatePromise(PrepareCooperatePromise);
TH_EXPORT_CPP_API_UnprepareCooperateAsync(UnprepareCooperateAsync);
TH_EXPORT_CPP_API_UnprepareCooperatePromise(UnprepareCooperatePromise);
TH_EXPORT_CPP_API_ActivateCooperateAsync(ActivateCooperateAsync);
TH_EXPORT_CPP_API_ActivateCooperatePromise(ActivateCooperatePromise);
TH_EXPORT_CPP_API_DeactivateCooperateAsync(DeactivateCooperateAsync);
TH_EXPORT_CPP_API_DeactivateCooperatePromise(DeactivateCooperatePromise);
TH_EXPORT_CPP_API_GetCooperateSwitchStateAsync(GetCooperateSwitchStateAsync);
TH_EXPORT_CPP_API_GetCooperateSwitchStatePromise(GetCooperateSwitchStatePromise);
TH_EXPORT_CPP_API_ActivateCooperateWithOptionsPromise(ActivateCooperateWithOptionsPromise);
TH_EXPORT_CPP_API_OnCooperateMessageInner(OnCooperateMessageInner);
TH_EXPORT_CPP_API_OffCooperateMessageInner(OffCooperateMessageInner);
TH_EXPORT_CPP_API_OnCooperateMouseEventInner(OnCooperateMouseEventInner);
TH_EXPORT_CPP_API_OffCooperateMouseEventInner(OffCooperateMouseEventInner);
// NOLINTEND