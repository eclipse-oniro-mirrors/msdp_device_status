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

#include "ani_boomerang_manager.h"

#include <sys/types.h>
#include <unistd.h>

#undef LOG_TAG
#define LOG_TAG "metadataBinding"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

std::map<int32_t, sptr<AniBoomerangCallback>> callbacks_;
ani_ref g_objPromise;
ani_vm* AniBoomerangCallback::vm_ = {nullptr};

constexpr int32_t MAX_LENGTH = 128;
constexpr int32_t MIN_IMAGE_PIXEL = 1080;
constexpr char const *URL_CHARACTERES =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=|%";

bool AniBoomerangCallback::Init(uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    env_ = taihe::get_env();
    if (env_ ==  nullptr) {
        FI_HILOGE("%{public}s ANI Get env is nullptr", LOG_TAG);
        return false;
    }
    ani_status status = ANI_OK;
    if (ANI_OK != env_->GetVM(&vm_)) {
        FI_HILOGE("env GetVM faild");
        return false;
    }
    if (opq != 0) {
        FI_HILOGD("%{public}s beign init callback", LOG_TAG);
        funObject_ = reinterpret_cast<ani_object>(opq);
        if ((status = env_->GlobalReference_Create(funObject_, &ref_)) != ANI_OK) {
            FI_HILOGE("%{public}s create callback object failed, status = %{public}d", LOG_TAG, status);
            ref_ = nullptr;
            return false;
        }
    } else {
        if ((status = env_->Promise_New(&deferred_, &promise_)) != ANI_OK) {
            env_ = nullptr;
            deferred_ = nullptr;
            promise_ = nullptr;
            FI_HILOGE("%{public}s create promise object failed, status = %{public}d", LOG_TAG, status);
            return false;
        }
    }
    return true;
}

void AniBoomerangCallback::OnScreenshotResult(const DeviceStatus::BoomerangData& screenshotData) 
{
    std::thread([=]() {
        AniBoomerang::GetInstance()->OnScreenshot(screenshotData.type, screenshotData.status, false);
    }).detach();
}

void AniBoomerangCallback::OnNotifyMetadata(const std::string &metadata)
{
    ani_env* env = AniBoomerangCommon::GetInstance()->AttachAniEnv(vm_);
    if (env == nullptr) {
        FI_HILOGE("get env failed");
        return;
    }
    env_ = env;
    metadata_ = metadata;
    std::thread([this, metadata]() {
        if (this->metadata_.empty()) {
            FI_HILOGE("%{public}s metadata_ is empty", LOG_TAG);
            return;
        }
        ani_status status = ANI_OK;
        ani_string metadataStr{};
        auto env = AniBoomerangCommon::GetInstance()->AttachAniEnv(vm_);
        if (env == nullptr) {
            FI_HILOGE("env == nullptr");
        }

        status = env->String_NewUTF8(metadata.c_str(), metadata.size(), &metadataStr);
        if (status != ANI_OK) {
            FI_HILOGE("Failed to create string, status = %{public}d", status);
            return;
        }
        env->PromiseResolver_Resolve(reinterpret_cast<ani_resolver>(this->promise_),
            static_cast<ani_ref>(metadataStr));
        vm_->DetachCurrentThread();
    }).detach();
}

void AniBoomerangCallback::OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap)
{
    std::thread([vm = vm_, deferred = deferred_, pixelMap]() {
        ani_env* env = AniBoomerangCommon::GetInstance()->AttachAniEnv(vm);
        if (env == nullptr) {
            FI_HILOGE("get env failed");
            return;
        }
        if (env == nullptr || pixelMap == nullptr) {
            FI_HILOGI("EmitOnEncodeImage pixelMap is nullptr");
            return;
        }
        AniBoomerang::GetInstance()->OnEncodeImage(env, pixelMap, deferred);
    }).detach();
}

AniBoomerang::AniBoomerang()
{
    env_ = taihe::get_env();
    ref_ = nullptr;
    DeviceStatusClient::GetInstance().RegisterDeathListener([this] {
        FI_HILOGI("%{public}s Receive death notification", LOG_TAG);
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.clear();
        ClearEventMap();
    });
}

AniBoomerang::~AniBoomerang()
{
    if (ref_ != nullptr) {
        env_->GlobalReference_Delete(ref_);
    }
    env_ = nullptr;
}

std::shared_ptr<AniBoomerang> AniBoomerang::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<AniBoomerang> instance_;
 
    std::call_once(flag, []() {
        instance_ = std::make_shared<AniBoomerang>();
    });
    return instance_;
}

void AniBoomerang::OnMetadata(const std::string &bundleName, ::taihe::callback_view<void(int32_t info)> handle,
    uintptr_t opq)
{
    if (bundleName.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    if (env_ == nullptr || ANI_OK != env_->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("%{public}s ani_env is nullptr or GlobalReference_Create failed", LOG_TAG);
        return;
    }
    if (!AniBoomerang::GetInstance()->On(BoomerangType::BOOMERANG_TYPE_BOOMERANG, callbackRef, false)) {
        FI_HILOGE("%{public}s type:%{public}d already exists", LOG_TAG, BoomerangType::BOOMERANG_TYPE_BOOMERANG);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (callbacks_.find(BoomerangType::BOOMERANG_TYPE_BOOMERANG) != callbacks_.end()) {
            FI_HILOGE("%{public}s key:%{public}d Callback exists", LOG_TAG, BoomerangType::BOOMERANG_TYPE_BOOMERANG);
            return;
        }
    }
    sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (callback == nullptr) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->Init(opq)) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        delete callback;
        return;
    }
    int32_t ret = ANI_BOOMERANG_MGR.SubscribeCallback(
        static_cast<BoomerangType>(BoomerangType::BOOMERANG_TYPE_BOOMERANG), bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, SUBSCRIBE_FAILED,
            MetadataBindingLogInfo.at(SUBSCRIBE_FAILED).c_str());
        taihe::set_business_error(SUBSCRIBE_FAILED, MetadataBindingLogInfo.at(SUBSCRIBE_FAILED));
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.insert(std::pair<int32_t, sptr<AniBoomerangCallback>>(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, callback));
}

void AniBoomerang::OffMetadata(const std::string &bundleName, ::taihe::optional_view<uintptr_t> opq)
{
    if (bundleName.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    if (!opq.has_value()) {
        FI_HILOGD("%{public}s opq is nullptr!", LOG_TAG);
        return;
    }
    if (!AniBoomerang::GetInstance()->Off(BoomerangType::BOOMERANG_TYPE_BOOMERANG)) {
        FI_HILOGE("%{public}s Not ready to unsubscribe for type:%{public}d", LOG_TAG,
            BoomerangType::BOOMERANG_TYPE_BOOMERANG);
        return;
    }
    sptr<AniBoomerangCallback> callback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto item = callbacks_.find(BoomerangType::BOOMERANG_TYPE_BOOMERANG);
        if (item == callbacks_.end()) {
            FI_HILOGE("%{public}s No existed callbacks_", LOG_TAG);
            return;
        }
        callback = item->second;
    }
    int32_t ret = ANI_BOOMERANG_MGR.UnsubscribeCallback(
        static_cast<BoomerangType>(BoomerangType::BOOMERANG_TYPE_BOOMERANG), bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, UNSUBSCRIBE_FAILED,
            MetadataBindingLogInfo.at(UNSUBSCRIBE_FAILED).c_str());
        taihe::set_business_error(UNSUBSCRIBE_FAILED, MetadataBindingLogInfo.at(UNSUBSCRIBE_FAILED));
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.erase(BoomerangType::BOOMERANG_TYPE_BOOMERANG);
    }
}

void AniBoomerang::NotifyMetadataBindingEvent(const std::string &bundleName, ani_object& promise)
{
    if (bundleName.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (callback == nullptr) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->Init()) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        delete callback;
        return;
    }
    if (callback->env_->GlobalReference_Create(callback->promise_, &g_objPromise) != ANI_OK) {
        FI_HILOGE("%{public}s Failed to create global reference", LOG_TAG);
        return;
    }
    promise = reinterpret_cast<ani_object>(g_objPromise);
    callback->promise_ = reinterpret_cast<ani_object>(g_objPromise);
    vm_ = callback->vm_;
    std::thread([this, bundleName, callback]() {
        auto ret = ANI_BOOMERANG_MGR.NotifyMetadataBindingEvent(bundleName, callback);
        callback->vm_->DetachCurrentThread();
        ani_env* env = AniBoomerangCommon::GetInstance()->AttachAniEnv(callback->vm_);
        if (env == nullptr) {
            FI_HILOGE("get env failed");
            return;
        }
        ProcessErrorResult(env, ret, HANDLER_FAILD, callback->deferred_);
        callback->vm_->DetachCurrentThread();
    }).detach();
    return;
}

void AniBoomerang::SubmitMetadata(const std::string &metadata)
{
    int32_t ret = ANI_BOOMERANG_MGR.SubmitMetadata(metadata);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:Internal handling failed. File creation failed.",
            LOG_TAG, HANDLER_FAILD);
        taihe::set_business_error(HANDLER_FAILD, "Internal handling failed. File creation failed.");
    }
}

void AniBoomerang::EncodeImage(uintptr_t srcImage, const std::string &metadata, ani_object& promise)
{
    if (!srcImage || metadata.empty() || static_cast<int32_t>(metadata.size()) > MAX_LENGTH) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (callback == nullptr) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->Init()) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        delete callback;
        return;
    }
    promise = callback->promise_;
    auto vm = callback->vm_;
    std::thread([this, vm, srcImage, metadata, callback]() {
        ani_object object = reinterpret_cast<ani_object>(srcImage);
        ani_env* env = AniBoomerangCommon::GetInstance()->AttachAniEnv(vm);
        if (env == nullptr) {
            FI_HILOGE("%{public}s get env failed", LOG_TAG);
            return;
        }
        std::shared_ptr<OHOS::Media::PixelMap> pixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env, object);
        if (pixelMap == nullptr) {
            FI_HILOGE("%{public}s get pixelMap failed", LOG_TAG);
            return;
        }
        size_t pos = metadata.find_first_not_of(URL_CHARACTERES);
        if (pos != std::string::npos) {
            FI_HILOGE("%{public}s There are illegal characters present in metadata", LOG_TAG);
            return;
        }
        if (pixelMap->GetWidth() < MIN_IMAGE_PIXEL || pixelMap->GetHeight() < MIN_IMAGE_PIXEL) {
            FI_HILOGE("%{public}s The image size does not meet the requirements", LOG_TAG);
            return;
        }
        int32_t ret = ANI_BOOMERANG_MGR.BoomerangEncodeImage(pixelMap, metadata, callback);
        ProcessErrorResult(env, ret, ENCODE_FAILED, callback->deferred_);
    }).detach();
}

void AniBoomerang::DecodeImage(uintptr_t encodedImage, ani_object& promise)
{
    if (!encodedImage) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    ani_object object = reinterpret_cast<ani_object>(encodedImage);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env_, object);
    sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (callback == nullptr) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->Init()) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        delete callback;
        return;
    }
    promise = callback->promise_;
    auto vm = callback->vm_;
    std::thread([this, vm, pixelMap, callback]() {
        auto ret = ANI_BOOMERANG_MGR.BoomerangDecodeImage(pixelMap, callback);
        ani_env* env = AniBoomerangCommon::GetInstance()->AttachAniEnv(vm);
        if (env == nullptr) {
            FI_HILOGE("get env failed");
            return;
        }
        ProcessErrorResult(env, ret, DECODE_FAILED, callback->deferred_);
    }).detach();
}

void AniBoomerang::OnScreenshot(int32_t type, int32_t status, bool isOnce)
{
    OnEvent(type, status, isOnce);
}

void AniBoomerang::OnEncodeImage(ani_env *env, std::shared_ptr<Media::PixelMap> pixelMap,
    ani_resolver deferred)
{
    ani_status status = ANI_OK;
    ani_object pixelMapObj = OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(env, pixelMap);
    if ( (status = env->PromiseResolver_Resolve(deferred, pixelMapObj)) != ANI_OK ) {
        FI_HILOGE("Failed to resolve deferred, status = %{public}d", status);
    }
}

void AniBoomerang::ProcessErrorResult(ani_env* env, int32_t result, int32_t code, ani_resolver deferred)
{
    if (env == nullptr || !deferred) {
        FI_HILOGE("Parameter error for %{public}d. Please check", code);
        return;
    }

    int32_t callResult = (result == RET_ERR) ? code : result;

    FI_HILOGI("callback the error result:%{public}d", callResult);

    ani_object statusAni = AniBoomerangCommon::GetInstance()->CreateAniInt(env, callResult);
    ani_status status = ANI_OK;
    if (result == RET_OK) {
        if ((status = env->PromiseResolver_Resolve(deferred, statusAni)) != ANI_OK) {
            FI_HILOGE("promise resolve failed, status = %{public}d", status);
        }
    } else {
        if ((status = env->PromiseResolver_Reject(deferred, static_cast<ani_error>(statusAni))) != ANI_OK) {
            FI_HILOGE("promise reject failed, status = %{public}d", status);
        }
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
