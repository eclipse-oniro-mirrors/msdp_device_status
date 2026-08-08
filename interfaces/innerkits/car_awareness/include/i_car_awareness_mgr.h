/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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


#ifndef ICAR_AWARENESS_MANAGER_H
#define ICAR_AWARENESS_MANAGER_H

#include <string>

namespace OHOS {
namespace CarAwareness {
using CarAwarenessCallback = std::function<void(const std::string &type, const std::string &result)>;

struct CarAwarenessOptions {
    std::vector<std::string> metadata_keys;
};

class ICarAwarenessMgr {
public:
    /**
     * @brief Destructor.
     * @return No return value.
     */
    virtual ~ICarAwarenessMgr() = default;

    /**
     * @brief Initializes the module.
     * @return Returns 0 on success, error code on failure.
     */
    virtual int32_t Initialize() = 0;

    /**
     * @brief Deinitializes the module/interface and releases resources.
     */
    virtual void Deinitialize() = 0;

    /**
     * @brief Retrieves all available capabilities.
     * @param[out] capabiltyVec Vector to be populated with all supported capabilities.
     */
    virtual void GetAllCapability(std::vector<std::string> &capabilities) = 0;

    /**
     * @brief Checks if a specific capability is supported.
     * @param capability The capability to check.
     * @return bool True if the capability is supported, false otherwise.
     */
    virtual bool IsCapabilitySupport(const std::string &capability) = 0;

    /**
     * @brief Registers a callback for car awareness notifications.
     * @param capability The capability to monitor.
     * @param callback The callback function to be invoked when awareness changes.
     * @param options Configuration options for car awareness monitoring.
     * @return Returns 0 on success, error code on failure.
     */
    virtual int32_t OnCarAwareness(const std::string &capability, CarAwarenessCallback callback,
                                const CarAwarenessOptions &options = CarAwarenessOptions()) = 0;

    /**
     * @brief Unregisters a car awareness callback.
     * @param capability The capability to stop monitoring.
     * @param callback The callback function to unregister (nullptr to unregister all).
     */
    virtual void OffCarAwareness(const std::string &capability, CarAwarenessCallback callback = nullptr) = 0;

    /**
     * @brief Updates the spatial action enable/disable status.
     * @param isEnable True to enable spatial actions, false to disable.
     * @return Returns 0 on success, error code on failure.
     */
    virtual int32_t UpdateSpatialActionStatus(bool isEnable) = 0;

    /**
     * @brief Updates the current spatial action zone.
     * @param zoneId The ID of the new spatial action zone.
     * @return Returns 0 on success, error code on failure.
     */
    virtual int32_t UpdateSpatialActionZone(int32_t zoneId) = 0;
};

using CreateCarAwarenessMgrFuncPtr = ICarAwarenessMgr *(*)(void);
}  // namespace CarAwareness
}  // namespace OHOS
#endif // ICAR_AWARENESS_MANAGER_H