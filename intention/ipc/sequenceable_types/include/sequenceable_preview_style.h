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

#ifndef SEQUENCEABLE_PREVIEW_STYLE_H
#define SEQUENCEABLE_PREVIEW_STYLE_H

#include <string>
#include <unistd.h>

#include "nocopyable.h"
#include "parcel.h"

#include "drag_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class SequenceablePreviewStyle : public Parcelable {
public:
    SequenceablePreviewStyle() = default;
    explicit SequenceablePreviewStyle(const PreviewStyle &previewStyle) : previewStyle_(previewStyle) {}
    virtual ~SequenceablePreviewStyle() = default;
     
    bool Marshalling(Parcel &parcel) const override;
    static SequenceablePreviewStyle* Unmarshalling(Parcel &parcel);

public:
    PreviewStyle previewStyle_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_PREVIEW_STYLE_H