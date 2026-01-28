/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <stdexcept>

#include "fi_log.h"
#include "ohos.multimodalAwareness.motion.proj.hpp"
#include "ohos.multimodalAwareness.motion.impl.hpp"
#include "taihe/runtime.hpp"

#ifdef MOTION_ENABLE
#include "motion_client.h"
#endif
#include "ani_motion_event.h"
#undef LOG_TAG
#define LOG_TAG "ANIMotion"

using OperatingHandStatus_t = ohos::multimodalAwareness::motion::OperatingHandStatus;
using HoldingHandStatus_t = ohos::multimodalAwareness::motion::HoldingHandStatus;

namespace {
using namespace OHOS::Msdp;
#ifdef MOTION_ENABLE
auto &g_motionClient = MotionClient::GetInstance();
#endif

OperatingHandStatus_t getRecentOperatingHandStatus()
{
    FI_HILOGI("getRecentOperatingHandStatus Enter");
    OperatingHandStatus_t status  = OperatingHandStatus_t::key_t::UNKNOWN_STATUS;
#ifdef MOTION_ENABLE
    FI_HILOGI("getRecentOperatingHandStatus Enter MOTION_ENABLE");
    MotionEvent motionEvent = g_motionClient.GetMotionData(MOTION_TYPE_OPERATING_HAND);
    if (motionEvent.status == DEVICE_EXCEPTION) {
        FI_HILOGE("Device not support");
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
        return status;
    }
    if (motionEvent.status == -1) {
        FI_HILOGE("Invalid Type");
        taihe::set_business_error(PERMISSION_DENIED, "Invalid Type");
        return status;
    }
    status = OperatingHandStatus_t::from_value(static_cast<int32_t>(motionEvent.status));
#else
    FI_HILOGI("getRecentOperatingHandStatus not Enter MOTION_ENABLE");
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
#endif
    FI_HILOGI("Exit");
    return status;
}

void OnOperatingHandChangedInner(taihe::callback_view<void(OperatingHandStatus_t)> f, uintptr_t opq)
{
    FI_HILOGI("OnOperatingHandChangedInner enter");
#ifdef MOTION_ENABLE
    FI_HILOGI("OnOperatingHandChangedInner Enter MOTION_ENABLE");
    if (!AniMotionEvent::GetInstance()->SubscribeCallback(MOTION_TYPE_OPERATING_HAND)) {
        FI_HILOGE("SubscribeCallback failed");
        return;
    }
    ::taihe::env_guard guard;
    ani_env *env = guard.get_env();
    ani_vm* vm = AniMotionEvent::GetInstance()->GetAniVm(env);
    if (!AniMotionEvent::GetInstance()->AddCallback(MOTION_TYPE_OPERATING_HAND, opq, vm)) {
        FI_HILOGE("AddCallback failed");
        taihe::set_business_error(SERVICE_EXCEPTION, "AddCallback failed");
        return;
    }
#else
    FI_HILOGI("OnOperatingHandChangedInner not Enter MOTION_ENABLE");
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
#endif
}

void OffOperatingHandChangedInner(::taihe::optional_view<uintptr_t> opq)
{
    FI_HILOGI("OffOperatingHandChangedInner enter");
#ifdef MOTION_ENABLE
    FI_HILOGI("OffOperatingHandChangedInner Enter MOTION_ENABLE");
    if (!opq.has_value()) {
        if (!AniMotionEvent::GetInstance()->RemoveAllCallback(MOTION_TYPE_OPERATING_HAND)) {
            FI_HILOGE("RemoveAllCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveAllCallback failed");
            return;
        }
    } else {
        if (!AniMotionEvent::GetInstance()->RemoveCallback(MOTION_TYPE_OPERATING_HAND, opq.value())) {
            FI_HILOGE("RemoveCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveCallback failed");
            return;
        }
    }
    if (!AniMotionEvent::GetInstance()->UnSubscribeCallback(MOTION_TYPE_OPERATING_HAND)) {
        FI_HILOGE("UnSubscribeCallback failed");
        return;
    }
#else
    FI_HILOGI("OffOperatingHandChangedInner not Enter MOTION_ENABLE");
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
#endif
}

void OnHoldingHandChangedInner(taihe::callback_view<void(HoldingHandStatus_t)> f, uintptr_t opq)
{
    FI_HILOGI("OnHoldingHandChangedInner enter");
#ifdef MOTION_ENABLE
    FI_HILOGI("OnHoldingHandChangedInner Enter MOTION_ENABLE");
    if (!AniMotionEvent::GetInstance()->SubscribeCallback(MOTION_TYPE_HOLDING_HAND)) {
        FI_HILOGE("SubscribeCallback failed");
        return;
    }
    ::taihe::env_guard guard;
    ani_env *env = guard.get_env();
    if (env == nullptr) {
        FI_HILOGE("get_env failed");
        taihe::set_business_error(SERVICE_EXCEPTION, "get_env failed");
        return;
    }
    ani_vm* vm = AniMotionEvent::GetInstance()->GetAniVm(env);
    if (vm == nullptr) {
        FI_HILOGE("GetAniVm failed");
        taihe::set_business_error(SERVICE_EXCEPTION, "GetAniVm failed");
        return;
    }
    if (!AniMotionEvent::GetInstance()->AddCallback(MOTION_TYPE_HOLDING_HAND, opq, vm)) {
        FI_HILOGE("AddCallback failed");
        taihe::set_business_error(SERVICE_EXCEPTION, "AddCallback failed");
        return;
    }
#else
    FI_HILOGI("OnHoldingHandChangedInner not Enter MOTION_ENABLE");
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
#endif
}

void OffHoldingHandChangedInner(::taihe::optional_view<uintptr_t> opq)
{
    FI_HILOGI("OffHoldingHandChangedInner enter");
#ifdef MOTION_ENABLE
    FI_HILOGI("OffHoldingHandChangedInner Enter MOTION_ENABLE");
    if (!opq.has_value()) {
        if (!AniMotionEvent::GetInstance()->RemoveAllCallback(MOTION_TYPE_HOLDING_HAND)) {
            FI_HILOGE("RemoveAllCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveAllCallback failed");
            return;
        }
    } else {
        if (!AniMotionEvent::GetInstance()->RemoveCallback(MOTION_TYPE_HOLDING_HAND, opq.value())) {
            FI_HILOGE("RemoveCallback failed");
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveCallback failed");
            return;
        }
    }
    if (!AniMotionEvent::GetInstance()->UnSubscribeCallback(MOTION_TYPE_HOLDING_HAND)) {
        FI_HILOGE("UnSubscribeCallback failed");
        return;
    }
#else
    FI_HILOGI("OffHoldingHandChangedInner not Enter MOTION_ENABLE");
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
#endif
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_getRecentOperatingHandStatus(getRecentOperatingHandStatus);
TH_EXPORT_CPP_API_OnOperatingHandChangedInner(OnOperatingHandChangedInner);
TH_EXPORT_CPP_API_OffOperatingHandChangedInner(OffOperatingHandChangedInner);
TH_EXPORT_CPP_API_OnHoldingHandChangedInner(OnHoldingHandChangedInner);
TH_EXPORT_CPP_API_OffHoldingHandChangedInner(OffHoldingHandChangedInner);
// NOLINTEND