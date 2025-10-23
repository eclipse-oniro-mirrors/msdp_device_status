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

#include "ohos.stationary.proj.hpp"
#include "ohos.stationary.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ani_devicestatus_manager.h"

namespace {
using namespace OHOS::Msdp::DeviceStatus;

void onActivity(::taihe::string_view activityType, ActivityEvent_t event, int64_t reportLatencyNs,
    ::taihe::callback_view<void(ActivityResponse_t const&)> f, uintptr_t opq)
{
    AniDeviceStatusManager::GetInstance()->SubscribeDeviceStatus(activityType.c_str(), event, reportLatencyNs, f, opq);
}

void offActivity(::taihe::string_view activityType, ActivityEvent_t event, ::taihe::optional_view<uintptr_t> opq)
{
    AniDeviceStatusManager::GetInstance()->UnsubscribeDeviceStatus(activityType.c_str(), event, opq);
}

void getDeviceStatus(::taihe::string_view activityType, ::taihe::callback_view<void(ActivityResponse_t const&)> f,
    uintptr_t opq)
{
    AniDeviceStatusManager::GetInstance()->GetDeviceStatus(activityType.c_str(), f, opq);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_onActivity(onActivity);
TH_EXPORT_CPP_API_offActivity(offActivity);
TH_EXPORT_CPP_API_getDeviceStatus(getDeviceStatus);
// NOLINTEND
