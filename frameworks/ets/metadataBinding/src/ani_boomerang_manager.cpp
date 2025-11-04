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
 
#undef LOG_TAG
#define LOG_TAG "metadataBinding"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
#define BOOMERANG_ALGO_SO_PATH "system/lib64/libmsdp_boomerang_algo.z.so"
 
std::map<int32_t, sptr<AniBoomerangCallback>> callbacks_;
 
bool AniBoomerangCallback::init(uintptr_t opq)
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
        if ((status= env_->GlobalReference_Create(funObject_, &ref_)) != ANI_OK) {
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
 
void AniBoomerangCallback::OnScreenshotResult(const DeviceStatus::BoomerangData& screentshotData)
{
    std::lock_guard<std::mutex> guard(mutex_);
    data_ = screentshotData;
    AniBoomerang::GetInstance()->OnScreenshot(data_.type, data_.status, false);
}
 
void AniBoomerangCallback::OnNotifyMetadata(const std::string &metadata)
{
    if (metadata.empty()) {
        FI_HILOGE("arguments is null");
        return;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    this->metadata_ = metadata;
    EmitOnMetadata(*env_, metadata);
}
 
void AniBoomerangCallback::EmitOnMetadata(ani_env env, std::string metadata)
{
    if (metadata.empty()) {
        FI_HILOGE("arguments is null");
        return;
    }
    AniBoomerang::GetInstance()->setDeferred(metadata);
}
 
AniBoomerang::AniBoomerang() : AniBoomerangEvent()
{
    env_ = taihe::get_env();
    ref_ = nullptr;
    DeviceStatusClient::GetInstance().RegisterDeathListener([this] {
        FI_HILOGI("%{public}s Receive death notification", LOG_TAG);
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
 
void AniBoomerang::onMetadata(std::string bundleName, ::taihe::callback_view<void(int32_t info)> handle, uintptr_t opq)
{
    if (bundleName.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
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
    if (callbacks_.find(BoomerangType::BOOMERANG_TYPE_BOOMERANG) != callbacks_.end()) {
        FI_HILOGE("%{public}s key:%{public}d Callback exists", LOG_TAG, BoomerangType::BOOMERANG_TYPE_BOOMERANG);
        return;
    }
    sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (nullptr == callback) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->init(opq)) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        return;
    }
    int32_t ret = ANI_BOOMERANG_MGR.SubscribeCallback(
        static_cast<BoomerangType>(BoomerangType::BOOMERANG_TYPE_BOOMERANG), bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, SUBSCRIBE_FAILED,
            MetadataBindingLogInfo.at(SUBSCRIBE_FAILED).c_str());
        taihe::set_business_error(SUBSCRIBE_FAILED, MetadataBindingLogInfo.at(SUBSCRIBE_FAILED));
    }
    callbacks_.insert(std::pair<int32_t, sptr<AniBoomerangCallback>>(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, callback));
}
 
void AniBoomerang::offMetadata(std::string bundleName, ::taihe::optional_view<uintptr_t> opq)
{
    FI_HILOGD("%{public}s unRegisterListener enter", LOG_TAG);
    if (bundleName.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!opq.has_value()) {
        FI_HILOGD("%{public}s opq is nullptr!", LOG_TAG);
        return;
    }
    if (!AniBoomerang::GetInstance()->Off(BoomerangType::BOOMERANG_TYPE_BOOMERANG)) {
        FI_HILOGE("%{public}s Not ready to unsubscribe for type:%{public}d", LOG_TAG,
            BoomerangType::BOOMERANG_TYPE_BOOMERANG);
        return;
    }
    auto item = callbacks_.find(BoomerangType::BOOMERANG_TYPE_BOOMERANG);
    if (item == callbacks_.end()) {
        FI_HILOGE("%{public}s No existed callbacks_", LOG_TAG);
        return;
    }
    int32_t ret = ANI_BOOMERANG_MGR.UnsubscribeCallback(
        static_cast<BoomerangType>(BoomerangType::BOOMERANG_TYPE_BOOMERANG), bundleName, item->second);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, UNSUBSCRIBE_FAILED,
            MetadataBindingLogInfo.at(UNSUBSCRIBE_FAILED).c_str());
        taihe::set_business_error(UNSUBSCRIBE_FAILED, MetadataBindingLogInfo.at(UNSUBSCRIBE_FAILED));
    }
    callbacks_.erase(BoomerangType::BOOMERANG_TYPE_BOOMERANG);
}
 
void AniBoomerang::notifyMetadataBindingEvent(std::string bundleName, ani_object& promise)
{
    if (bundleName.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    FI_HILOGD("%{public}s notifyMetadataBindingEventPromise enter", LOG_TAG);
    std::lock_guard<std::mutex> lock(mutex_);
    OHOS::sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (nullptr == callback) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->init()) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        return;
    }
    promise = callback->promise_;
    int32_t ret = ANI_BOOMERANG_MGR.NotifyMetadataBindingEvent(bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, HANDLER_FAILD,
            MetadataBindingLogInfo.at(HANDLER_FAILD).c_str());
        taihe::set_business_error(HANDLER_FAILD, MetadataBindingLogInfo.at(HANDLER_FAILD));
    }
}
 
void AniBoomerang::submitMetadata(std::string metadata)
{
    if (metadata.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    FI_HILOGD("%{public}s submitMetadataPromise enter", LOG_TAG);
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = ANI_BOOMERANG_MGR.SubmitMetadata(metadata);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:Internal handling failed. File creation failed.",
            LOG_TAG, HANDLER_FAILD);
        taihe::set_business_error(HANDLER_FAILD, "Internal handling failed. File creation failed.");
    }
}
 
void AniBoomerang::encodeImage(uintptr_t srcImage, std::string metadata, ani_object& promise)
{
    if (!srcImage || metadata.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    FI_HILOGD("%{public}s encodeImagePromise enter", LOG_TAG);
    std::lock_guard<std::mutex> lock(mutex_);
    OHOS::sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (nullptr == callback) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->init()) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        return;
    }
    promise = callback->promise_;
    ani_object object = reinterpret_cast<ani_object>(srcImage);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env_, object);
    int32_t ret = ANI_BOOMERANG_MGR.BoomerangEncodeImage(pixelMap, metadata, callback);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, ENCODE_FAILED,
            MetadataBindingLogInfo.at(ENCODE_FAILED).c_str());
        taihe::set_business_error(ENCODE_FAILED, MetadataBindingLogInfo.at(ENCODE_FAILED));
    }
}
 
void AniBoomerang::decodeImage(uintptr_t encodedImage, ani_object& promise)
{
    if (!encodedImage) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    ani_object object = reinterpret_cast<ani_object>(encodedImage);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env_, object);
    OHOS::sptr<AniBoomerangCallback> callback = new (std::nothrow) AniBoomerangCallback();
    if (nullptr == callback) {
        FI_HILOGE("%{public}s callback is nullptr", LOG_TAG);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "callback is nullptr");
        return;
    }
    if (!callback->init()) {
        FI_HILOGE("%{public}s AniBoomerangCallback init fail", LOG_TAG);
        taihe::set_business_error(OTHER_ERROR, "AniBoomerangCallback init fail");
        return;
    }
    promise = callback->promise_;
    std::string content;
    DecodeImageFunc(pixelMap, content);
    int32_t ret = ANI_BOOMERANG_MGR.BoomerangDecodeImage(pixelMap, callback);
    if (ret != RET_OK) {
        FI_HILOGE("%{public}s type:%{public}d return fail,err msg:%{public}s.", LOG_TAG, DECODE_FAILED,
            MetadataBindingLogInfo.at(DECODE_FAILED).c_str());
        taihe::set_business_error(DECODE_FAILED, MetadataBindingLogInfo.at(DECODE_FAILED));
    }
}
 
bool AniBoomerang::EncodeImageFunc(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, const std::string &content,
    std::shared_ptr<OHOS::Media::PixelMap> &resultPixelMap)
{
    if (pixelMap == nullptr || content.empty()) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return false;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(BOOMERANG_ALGO_SO_PATH, realPath) == nullptr) {
        FI_HILOGE("%{public}s %{public}s Path is error", LOG_TAG, realPath);
        return false;
    }
    void *handle = dlopen(realPath, RTLD_LAZY);
    char *error = nullptr;
    if (handle == nullptr) {
        FI_HILOGE("%{public}s handle is null", LOG_TAG);
        return false;
    }
    EncodeImagePtr encodeImage = reinterpret_cast<EncodeImagePtr>(dlsym(handle, "EncodeImage"));
    if ((error = dlerror()) != nullptr || encodeImage == nullptr) {
        FI_HILOGE("%{public}s Boomerang Algo Encode find symbol failed, error: %{public}s", LOG_TAG, error);
        dlclose(handle);
        return false;
    }
    encodeImage(pixelMap, content, resultPixelMap);
    dlclose(handle);
    FI_HILOGD("%{public}s Boomerang Algo Encode success", LOG_TAG);
    return true;
}
 
bool AniBoomerang::DecodeImageFunc(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, std::string &content)
{
    if (pixelMap == nullptr) {
        FI_HILOGE("%{public}s Failed to get arguments", LOG_TAG);
        return false;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(BOOMERANG_ALGO_SO_PATH, realPath) == nullptr) {
        FI_HILOGE("%{public}s %{public}s Path is error", LOG_TAG, realPath);
        return false;
    }
    void *handle = dlopen(realPath, RTLD_LAZY);
    char *error = nullptr;
    if (handle == nullptr) {
        FI_HILOGE("%{public}s handle is null", LOG_TAG);
        return false;
    }
    DecodeImagePtr decodeImageFunc = reinterpret_cast<DecodeImagePtr>(dlsym(handle, "DecodeImage"));
    if (((error = dlerror()) != nullptr) || (decodeImageFunc == nullptr)) {
        dlclose(handle);
        FI_HILOGE("%{public}s Boomerang Algo Decode find symbol failed, error: %{public}s", LOG_TAG, error);
        return false;
    }
    decodeImageFunc(pixelMap, content);
    dlclose(handle);
    FI_HILOGD("%{public}s Boomerang Algo Decode success", LOG_TAG);
    return true;
}
 
void AniBoomerang::setDeferred(std::string data)
{
    this->metadata_ = data;
}
 
void AniBoomerang::OnScreenshot(int32_t type, int32_t status, bool isOnce)
{
    OnEvent(type, status, isOnce);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS