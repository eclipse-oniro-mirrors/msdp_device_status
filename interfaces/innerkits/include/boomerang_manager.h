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

#ifndef BOOMERANG_MANAGER_H
#define BOOMERANG_MANAGER_H

#include <functional>
#include <memory>

#include "nocopyable.h"

#include "boomerang_data.h"
#include "devicestatus_common.h"
#include "iremote_boomerang_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangManager {
public:

    /**
     * @brief Obtains a <b>BoomerangManager</b> instance.
     * @return Returns a <b>BoomerangManager</b> instance.
     * @since 15
     */
    static BoomerangManager& GetInstance();

    /**
     * @brief Subscribes to boomerang event changes.
     * @param type Indicates the device status type.
     * @param bundleName Third-party application package name.
     * @param callback Indicates the callback used to return the boomerang for screenshot event.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 15
     */
    int32_t SubscribeCallback(BoomerangType type, const std::string &bundleName,
        sptr<IRemoteBoomerangCallback> callback);

    /**
     * @brief Unsubscribes from boomerang event changes.
     * @param type Indicates the boomerang type.
     * @param bundleName Third-party application package name.
     * @param callback Unregistered callback event.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 15
     */
    int32_t UnsubscribeCallback(BoomerangType type, const std::string &bundleName,
        sptr<IRemoteBoomerangCallback> callback);

    /**
     * @brief Screenshot application obtaining applink information.
     * @param bundleName Third-party application package name.
     * @param callback Third-party app callback applink.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 15
     */
    int32_t NotifyMetadataBindingEvent(const std::string &bundleName, sptr<IRemoteBoomerangCallback> callback);

    /**
     * @brief Third-party app backhauls applink information.
     * @param metadata applink information.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 15
     */
    int32_t SubmitMetadata(const std::string &metadata);

    /**
     * @brief boomerang encode image.
     * @param pixelMap Images that need to be boomerang coded.
     * @param matedata Encoding content.
     * @param callback Callback function that is called back to the client after encoding.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 15
     */
    int32_t BoomerangEncodeImage(std::shared_ptr<Media::PixelMap> pixelMap, const std::string &metedata,
        sptr<IRemoteBoomerangCallback> callback);

        /**
     * @brief boomerang decode image.
     * @param pixelMap Images containing Boomerang coded information.
     * @param callback Callback function that is called back to the client after decoding.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 15
     */
    int32_t BoomerangDecodeImage(std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback);
private:
    BoomerangManager() = default;
    ~BoomerangManager() = default;
    DISALLOW_COPY_AND_MOVE(BoomerangManager);
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_MANAGER_H