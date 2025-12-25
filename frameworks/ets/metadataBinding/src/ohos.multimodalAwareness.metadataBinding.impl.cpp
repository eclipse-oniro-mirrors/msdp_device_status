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

#include "ani_boomerang_manager.h"
#include <sys/types.h>
#include <unistd.h>

#undef LOG_TAG
#define LOG_TAG "metadataBindingImpl"

namespace {
using namespace ::taihe;
using namespace OHOS::Msdp::DeviceStatus;
void onMetadataInner(::taihe::string_view bundleName, ::taihe::callback_view<void(int32_t info)> callbck, uintptr_t opq)
{
    AniBoomerang::GetInstance()->OnMetadata(std::string(bundleName), callbck, opq);
}

void offMetadataInner(::taihe::string_view bundleName, ::taihe::optional_view<uintptr_t> opq)
{
    AniBoomerang::GetInstance()->OffMetadata(std::string(bundleName), opq);
}

::taihe::string notifyMetadataBindingEventPromise(::taihe::string_view bundleName)
{
    std::string metadata = AniBoomerang::GetInstance()->NotifyMetadataBindingEvent(std::string(bundleName));
    return ::taihe::string(metadata.c_str());
}

void submitMetadata(::taihe::string_view metadata)
{
    AniBoomerang::GetInstance()->SubmitMetadata(std::string(metadata));
}

uintptr_t encodeImagePromise(uintptr_t srcImage, ::taihe::string_view metadata)
{
    ani_object image = AniBoomerang::GetInstance()->EncodeImage(srcImage, std::string(metadata));
    return reinterpret_cast<uintptr_t>(image);
}

::taihe::string decodeImagePromise(uintptr_t encodedImage)
{
    std::string imageStr = AniBoomerang::GetInstance()->DecodeImage(encodedImage);
    return ::taihe::string(imageStr.c_str());
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_onMetadataInner(onMetadataInner);
TH_EXPORT_CPP_API_offMetadataInner(offMetadataInner);
TH_EXPORT_CPP_API_submitMetadata(submitMetadata);
TH_EXPORT_CPP_API_notifyMetadataBindingEventPromise(notifyMetadataBindingEventPromise);
TH_EXPORT_CPP_API_encodeImagePromise(encodeImagePromise);
TH_EXPORT_CPP_API_decodeImagePromise(decodeImagePromise);
// NOLINTEND
