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

#include "sequenceable_fuzzer.h"

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
#define LOG_TAG "SequenceableFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr uint32_t RANGE = 5;
constexpr uint64_t RANGEINT = 5;
constexpr int32_t RANGEMAX = 10;
}
namespace OHOS {
bool SequenceableFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Parcel parcel;
    PreviewStyle previewStyle;
    previewStyle.foregroundColor = provider.ConsumeIntegralInRange<uint32_t>(0, RANGE);
    previewStyle.opacity = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    previewStyle.radius = provider.ConsumeFloatingPointInRange<float>(0, 1);
    previewStyle.scale = provider.ConsumeFloatingPointInRange<float>(0, 1);
    PreviewAnimation previewAnimation;
    previewAnimation.curveName = provider.ConsumeRandomLengthString();
    previewAnimation.duration = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    SequenceablePreviewAnimation sequenceablePreviewAnimation(previewStyle, previewAnimation);
    SequenceablePreviewAnimation *sequenceablePreviewAnimation1 = sequenceablePreviewAnimation.Unmarshalling(parcel);
    if (sequenceablePreviewAnimation1 != nullptr) {
        sequenceablePreviewAnimation1->Marshalling(parcel);
    }
    SequenceablePreviewStyle sequenceablePreviewStyle(previewStyle);
    SequenceablePreviewStyle *sequenceablePreviewStyle1 = sequenceablePreviewStyle.Unmarshalling(parcel);
    if (sequenceablePreviewStyle1 != nullptr) {
        sequenceablePreviewStyle1->Marshalling(parcel);
    }
    DragDropResult dropResult;
    dropResult.hasCustomAnimation = provider.ConsumeBool();
    dropResult.mainWindow = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    SequenceableDragResult sequenceableDragResult(dropResult);
    SequenceableDragResult *sequenceDragResult1 = sequenceableDragResult.Unmarshalling(parcel);
    if (sequenceDragResult1 != nullptr) {
        sequenceDragResult1->Marshalling(parcel);
    }
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    DragVisibleParam dragVisibleParam;
    dragVisibleParam.visible = provider.ConsumeBool();
    dragVisibleParam.isForce = provider.ConsumeBool();
    dragVisibleParam.rsTransaction = rsTransaction;
    SequenceableDragVisible sequenceableDragVisible(dragVisibleParam);
    SequenceableDragVisible *sequenceableDragVisible1 = sequenceableDragVisible.Unmarshalling(parcel);
    if (sequenceableDragVisible1  == nullptr) {
        sequenceableDragVisible1->Marshalling(parcel);
    }
    SequenceableRotateWindow sequenceableRotateWindow(rsTransaction);
    SequenceableRotateWindow *sequenceableRotateWindow1 = sequenceableRotateWindow.Unmarshalling(parcel);
    if (sequenceableRotateWindow1  == nullptr) {
        sequenceableRotateWindow1->Marshalling(parcel);
    }
    return true;
}

bool Sequenceable1FuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Parcel parcel;
    PreviewStyle previewStyle;
    PreviewAnimation animation;
    animation.curveName = provider.ConsumeRandomLengthString();
    animation.duration = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    SequenceablePreviewAnimation sequenceablePreviewAnimation2(previewStyle, animation);
    SequenceablePreviewAnimation *sequenceablePreviewAnimation3 = sequenceablePreviewAnimation2.Unmarshalling(parcel);
    if (sequenceablePreviewAnimation3 != nullptr) {
        sequenceablePreviewAnimation3->Marshalling(parcel);
    }
    DevicePostureData data1;
    data1.pitchRad = provider.ConsumeFloatingPointInRange<float>(0, 1);
    data1.rollRad = provider.ConsumeFloatingPointInRange<float>(0, 1);
    data1.yawRad = provider.ConsumeFloatingPointInRange<float>(0, 1);
    SequenceablePostureData postureData;
    postureData.SetPostureData(data1);
    SequenceablePostureData *postureData1 =  postureData.Unmarshalling(parcel);
    if (postureData1 != nullptr) {
        postureData1->Marshalling(parcel);
    }
    OnScreen::ContentOption option;
    option.windowId = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    option.contentUnderstand = provider.ConsumeBool();
    option.pageLink = provider.ConsumeBool();
    option.textOnly = provider.ConsumeBool();
    option.paragraphSizeRange.minSize = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    option.paragraphSizeRange.maxSize = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    OnScreen::SequenceableContentOption contentOption(option);
    OnScreen::SequenceableContentOption *contentOption1 = contentOption.Unmarshalling(parcel);
    if (contentOption1 != nullptr) {
        contentOption1->Marshalling(parcel);
    }
    OnScreen::ControlEvent controlEvent;
    controlEvent.windowId = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX);
    controlEvent.sessionId = provider.ConsumeIntegralInRange<int64_t>(0, RANGEINT);
    controlEvent.eventType = static_cast<OnScreen::EventType>(provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX));
    controlEvent.hookId = provider.ConsumeIntegralInRange<int64_t>(0, RANGEINT);
    OnScreen::SequenceableControlEvent event(controlEvent);
    OnScreen::SequenceableControlEvent *event1 = event.Unmarshalling(parcel);
    if (event1 != nullptr) {
        event1->Marshalling(parcel);
    }
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::SequenceableFuzzTest(data, size);
    OHOS::Sequenceable1FuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS