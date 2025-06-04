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

#include "sequenceable_preview_style.h"

#include "devicestatus_define.h"
#include "preview_style_packer.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceablePreviewStyle::Marshalling(Parcel &parcel) const
{
    if (PreviewStylePacker::Marshalling(previewStyle_, parcel) != RET_OK) {
        return false;
    }
    return true;
}

SequenceablePreviewStyle* SequenceablePreviewStyle::Unmarshalling(Parcel &parcel)
{
    SequenceablePreviewStyle *sequenceablePreviewStyle = new (std::nothrow) SequenceablePreviewStyle();
    CHKPP(sequenceablePreviewStyle);
    if (PreviewStylePacker::UnMarshalling(parcel, sequenceablePreviewStyle->previewStyle_) != RET_OK) {
        delete sequenceablePreviewStyle;
        return nullptr;
    }
    return sequenceablePreviewStyle;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS