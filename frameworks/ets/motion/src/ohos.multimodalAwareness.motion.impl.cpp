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

#include "ohos.multimodalAwareness.motion.proj.hpp"
#include "ohos.multimodalAwareness.motion.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "fi_log.h"

using OperatingHandStatus_t = ohos::multimodalAwareness::motion::OperatingHandStatus;

namespace {
using namespace OHOS::Msdp;
#ifdef MOTION_ENABLE
auto &g_motionClient = MotionClient::GetInstance();
#endif
constexpr int32_t DEVICE_EXCEPTION { 801 };
// To be implemented.

OperatingHandStatus_t getRecentOperatingHandStatus()
{
    FI_HILOGD("Enter");
    OperatingHandStatus_t status  = OperatingHandStatus_t::key_t::UNKNOWN_STATUS;
#ifdef MOTION_ENABLE
    MotionEvent motionEvent = g_motionClient.GetMotionData(MOTION_TYPE_OPERATING_HAND);
    if (motionEvent.status == DEVICE_EXCEPTION) {
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
        return status;
    }
    if (motionEvent.status == -1) {
        taihe::set_business_error(PERMISSION_EXCEPTION, "Invalid Type");
        return status;
    }
    status = OperatingHandStatus_t::from_value(static_cast<int32_t>(motionEvent.status));
#else
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
#endif
    FI_HILOGD("Exit");
    return status;
}

void OnOperatingHandChangedInner(taihe::callback_view<void(OperatingHandStatus_t)> f, uintptr_t opq)
{
#ifdef MOTION_ENABLE
    if (!AniMotionEvent::GetInstance()->SubscribeCallback(MOTION_TYPE_OPERATING_HAND)) {
        FI_HILOGE("SubscribeCallback failed");
        return;
    }
    if (!AniMotionEvent::GetInstance()->AddCallback(MOTION_TYPE_OPERATING_HAND, f, opq)) {
        ThrowMotionErr(env, SERVICE_EXCEPTION, "AddCallback failed");
        return;
    }
#else
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
    return;
#endif
}

void OffOperatingHandChangedInner(::taihe::optional_view<uintptr_t> opq)
{
#ifdef MOTION_ENABLE
    if (!opq.has_value()) {
        if (!AniMotionEvent::GetInstance()->RemoveAllCallback(MOTION_TYPE_OPERATING_HAND)) {
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveAllCallback failed");
            return;
        }
    } else {
        if (!AniMotionEvent::GetInstance()->RemoveCallback(MOTION_TYPE_OPERATING_HAND, opq.value())) {
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveCallback failed");
            return;
        }
    }
#else
    taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
    return;
#endif
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_getRecentOperatingHandStatus(getRecentOperatingHandStatus);
TH_EXPORT_CPP_API_OnOperatingHandChangedInner(OnOperatingHandChangedInner);
TH_EXPORT_CPP_API_OffOperatingHandChangedInner(OffOperatingHandChangedInner);
// NOLINTEND