/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sequenceablepagecontent_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"

#define private public
#include "sequenceable_content_option.h"
#include "sequenceable_control_event.h"
#include "sequenceable_cooperate_options.h"
#include "sequenceable_drag_data.h"
#include "sequenceable_drag_result.h"
#include "sequenceable_drag_summary_info.h"
#include "sequenceable_drag_visible.h"
#include "sequenceable_page_content.h"
#include "sequenceable_posture_data.h"
#include "sequenceable_preview_animation.h"
#include "sequenceable_preview_style.h"
#include "sequenceable_rotate_window.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "SequenceablePageContentFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t RANGEMAX = 10;
}
bool SequenceablePageContentFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Parcel parcel;
    OnScreen::PageContent content = {
        .windowId = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .sessionId = provider.ConsumeIntegralInRange<int64_t>(0, RANGEMAX),
        .bundleName = provider.ConsumeBytesAsString(RANGEMAX),
        .scenario = static_cast<Msdp::DeviceStatus::OnScreen::Scenario>(
            provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)),
        .title = provider.ConsumeBytesAsString(RANGEMAX),
        .content = provider.ConsumeBytesAsString(RANGEMAX),
        .pageLink = provider.ConsumeBytesAsString(RANGEMAX),
        .paragraphs = {
            {provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
                provider.ConsumeIntegralInRange<int64_t>(0, RANGEMAX),
                provider.ConsumeBytesAsString(RANGEMAX), provider.ConsumeBytesAsString(RANGEMAX)},
            {provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
                provider.ConsumeIntegralInRange<int64_t>(0, RANGEMAX),
                provider.ConsumeBytesAsString(RANGEMAX), provider.ConsumeBytesAsString(RANGEMAX)},
            {provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
                provider.ConsumeIntegralInRange<int64_t>(0, RANGEMAX),
                provider.ConsumeBytesAsString(RANGEMAX), provider.ConsumeBytesAsString(RANGEMAX)}
        }
    };
    OnScreen::SequenceablePageContent sequenceablePageContent(content);
    OnScreen::SequenceablePageContent *sequenceablePageContent1 = sequenceablePageContent.Unmarshalling(parcel);
    if (sequenceablePageContent1 != nullptr) {
        sequenceablePageContent1->Marshalling(parcel);
    }
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    SequenceablePageContentFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS