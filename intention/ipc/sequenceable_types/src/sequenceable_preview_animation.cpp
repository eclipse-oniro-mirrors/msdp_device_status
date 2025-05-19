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

#include "sequenceable_preview_animation.h"

#include "devicestatus_define.h"
#include "preview_style_packer.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceablePreviewAnimation::Marshalling(Parcel &parcel) const
{
    if ((PreviewStylePacker::Marshalling(previewStyle_, parcel) != RET_OK) ||
        (PreviewAnimationPacker::Marshalling(previewAnimation_, parcel) != RET_OK)) {
        return false;
    }
    return true;
}

SequenceablePreviewAnimation* SequenceablePreviewAnimation::Unmarshalling(Parcel &parcel)
{
    SequenceablePreviewAnimation *sequenceablePreviewAnimation = new (std::nothrow) SequenceablePreviewAnimation();
    CHKPP(sequenceablePreviewAnimation);
    if ((PreviewStylePacker::UnMarshalling(parcel, sequenceablePreviewAnimation->previewStyle_) != RET_OK) ||
        (PreviewAnimationPacker::UnMarshalling(parcel, sequenceablePreviewAnimation->previewAnimation_) != RET_OK)) {
        delete sequenceablePreviewAnimation;
        return nullptr;
    }
    return sequenceablePreviewAnimation;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS