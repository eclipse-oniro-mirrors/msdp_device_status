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

#include "singleton.h"

#define private public
#include "sequenceable_cooperate_options.h"
#include "sequenceable_drag_data.h"
#include "sequenceable_drag_result.h"
#include "sequenceable_drag_visible.h"
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
namespace OHOS {
const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };

bool SequenceableFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Write failed");
        return false;
    }
    PreviewStyle previewStyle;
    PreviewAnimation previewAnimation;
    Parcel parcel;
    SequenceablePreviewAnimation sequenceablePreviewAnimation(previewStyle, previewAnimation);
    sequenceablePreviewAnimation.Marshalling(parcel);
    sequenceablePreviewAnimation.Unmarshalling(parcel);
    SequenceablePreviewStyle sequenceablePreviewStyle(previewStyle);
    sequenceablePreviewStyle.Marshalling(parcel);
    sequenceablePreviewStyle.Unmarshalling(parcel);
    DragDropResult dropResult;
    SequenceableDragResult sequenceableDragResult(dropResult);
    sequenceableDragResult.Marshalling(parcel);
    sequenceableDragResult.Unmarshalling(parcel);
    bool visible = true;
    bool isForce = true;
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    DragVisibleParam dragVisibleParam;
    dragVisibleParam.visible = visible;
    dragVisibleParam.isForce = isForce;
    dragVisibleParam.rsTransaction = rsTransaction;
    SequenceableDragVisible sequenceableDragVisible(dragVisibleParam);
    sequenceableDragVisible.Marshalling(parcel);
    sequenceableDragVisible.Unmarshalling(parcel);
    SequenceableRotateWindow sequenceableRotateWindow(rsTransaction);
    sequenceableRotateWindow.Marshalling(parcel);
    sequenceableRotateWindow.Unmarshalling(parcel);
    PreviewAnimation animation;
    SequenceablePreviewAnimation sequenceablePreviewAnimation1(previewStyle, animation);
    sequenceablePreviewAnimation1.Marshalling(parcel);
    sequenceablePreviewAnimation1.Unmarshalling(parcel);
    SequenceablePostureData postureData;
    postureData.Marshalling(parcel);
    postureData.Unmarshalling(parcel);
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
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS