/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "ohos.multimodalAwareness.underageModel.proj.hpp"
#include "ohos.multimodalAwareness.underageModel.impl.hpp"
#include "taihe/runtime.hpp"
#include <stdexcept>
#include "fi_log.h"
#include "ani_underage_model_event.h"
#undef LOG_TAG
#define LOG_TAG "ANIUnderageModel"
namespace {
using namespace OHOS::Msdp;

void OnUserAgeGroupDetectedInner(::taihe::callback_view<void(UserClassification_t const& info)> f, uintptr_t opq)
{
    FI_HILOGI("OnUserAgeGroupDetectedInner enter");
    if (!AniUnderageModelEvent::GetInstance()->SubscribeCallback(UNDERAGE_MODEL_TYPE_KID)) {
        FI_HILOGE("SubscribeCallback failed");
        taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "AddCallback failed");
        return;
    }
    if (!AniUnderageModelEvent::GetInstance()->AddCallback(UNDERAGE_MODEL_TYPE_KID, opq)) {
        taihe::set_business_error(SERVICE_EXCEPTION, "AddCallback failed");
        return;
    }
    return;
}

void OffUserAgeGroupDetectedInner(::taihe::optional_view<uintptr_t> opq)
{
    FI_HILOGI("OffUserAgeGroupDetectedInner enter");
    if (!opq.has_value()) {
        if (!AniUnderageModelEvent::GetInstance()->RemoveAllCallback(UNDERAGE_MODEL_TYPE_KID)) {
            FI_HILOGE("RemoveAllCallback failed");
            taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "RemoveAllCallback failed");
            return;
        }
    } else {
        if (!AniUnderageModelEvent::GetInstance()->RemoveCallback(UNDERAGE_MODEL_TYPE_KID,
            opq.value())) {
            taihe::set_business_error(SERVICE_EXCEPTION, "RemoveCallback failed");
            return;
        }
    }
    return;
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnUserAgeGroupDetectedInner(OnUserAgeGroupDetectedInner);
TH_EXPORT_CPP_API_OffUserAgeGroupDetectedInner(OffUserAgeGroupDetectedInner);
// NOLINTEND