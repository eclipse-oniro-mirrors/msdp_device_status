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

#undef LOG_TAG
#define LOG_TAG "metadataBinding"

namespace {
using namespace ::taihe;
using namespace OHOS::Msdp::DeviceStatus;
void onMetadata(::taihe::string_view bundleName, ::taihe::callback_view<void(int32_t info)> callbck, uintptr_t opq)
{
    AniBoomerang::GetInstance()->onMetadata(std::string(bundleName), callbck, opq);
}

void offMetadata(::taihe::string_view bundleName, ::taihe::optional_view<uintptr_t> opq)
{
    AniBoomerang::GetInstance()->offMetadata(std::string(bundleName), opq);
}

uintptr_t notifyMetadataBindingEventPromise(::taihe::string_view bundleName)
{
    ani_object promise;
    AniBoomerang::GetInstance()->notifyMetadataBindingEvent(std::string(bundleName), promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void submitMetadata(::taihe::string_view metadata)
{
    AniBoomerang::GetInstance()->submitMetadata(std::string(metadata));
}

uintptr_t encodeImagePromise(uintptr_t srcImage, ::taihe::string_view metadata)
{
    ani_object promise;
    AniBoomerang::GetInstance()->encodeImage(srcImage, std::string(metadata), promise);
    return reinterpret_cast<uintptr_t>(promise);
}

uintptr_t decodeImagePromise(uintptr_t encodedImage)
{
    ani_object promise;
    AniBoomerang::GetInstance()->decodeImage(encodedImage, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_onMetadata(onMetadata);
TH_EXPORT_CPP_API_offMetadata(offMetadata);
TH_EXPORT_CPP_API_submitMetadata(submitMetadata);
TH_EXPORT_CPP_API_notifyMetadataBindingEventPromise(notifyMetadataBindingEventPromise);
TH_EXPORT_CPP_API_encodeImagePromise(encodeImagePromise);
TH_EXPORT_CPP_API_decodeImagePromise(decodeImagePromise);
// NOLINTEND