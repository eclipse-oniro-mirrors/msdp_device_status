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

#include "ohos.multimodalInput.inputDeviceCooperate.proj.hpp"
#include "ohos.multimodalInput.inputDeviceCooperate.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "fi_log.h"
#include "ani_cooperate_manager.h"

#undef LOG_TAG
#define LOG_TAG "AniCoopImpl"

namespace {
using namespace OHOS::Msdp::DeviceStatus;
using namespace OHOS::Msdp;

void EnableAsync(bool enableInput, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.Enable(enableInput, opq, promise);
    return;
}

uintptr_t EnablePromise(bool enableInput)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.Enable(enableInput, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void StartAsync(::taihe::string_view sinkDeviceDescriptor, int32_t srcInputDeviceId, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.Start(sinkDeviceDescriptor.c_str(), srcInputDeviceId, opq, promise);
}

uintptr_t StartPromise(::taihe::string_view sinkDeviceDescriptor, int32_t srcInputDeviceId)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.Start(sinkDeviceDescriptor.c_str(), srcInputDeviceId, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void StopAsync(uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.Stop(opq, promise);
}

uintptr_t StopPromise()
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.Stop(0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void GetStateAsync(::taihe::string_view deviceDescriptor, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.GetState(deviceDescriptor.c_str(), opq, promise);
}

uintptr_t GetStatePromise(::taihe::string_view deviceDescriptor)
{
    CALL_DEBUG_ENTER;
    ani_object promise;
    ANI_COOPERATE_MGR.GetState(deviceDescriptor.c_str(), 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void onCooperation(
    ::taihe::callback_view<void(CooperationCallbackData_t const& info)> callback, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ANI_COOPERATE_MGR.OnCooperation(opq);
}

void offCooperation(::taihe::optional_view<uintptr_t> opq) {
    CALL_DEBUG_ENTER;
    ANI_COOPERATE_MGR.OffCooperation(opq);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_EnableAsync(EnableAsync);
TH_EXPORT_CPP_API_EnablePromise(EnablePromise);
TH_EXPORT_CPP_API_StartAsync(StartAsync);
TH_EXPORT_CPP_API_StartPromise(StartPromise);
TH_EXPORT_CPP_API_StopAsync(StopAsync);
TH_EXPORT_CPP_API_StopPromise(StopPromise);
TH_EXPORT_CPP_API_GetStateAsync(GetStateAsync);
TH_EXPORT_CPP_API_GetStatePromise(GetStatePromise);
TH_EXPORT_CPP_API_onCooperation(onCooperation);
TH_EXPORT_CPP_API_offCooperation(offCooperation);
// NOLINTEND

