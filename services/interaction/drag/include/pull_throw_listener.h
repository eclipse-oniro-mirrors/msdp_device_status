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

#ifndef PULL_THROW_LISTENER_H
#define PULL_THROW_LISTENER_H

#include "data_ability_observer_stub.h"
#include "datashare_helper.h"
#include "display_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class DragManager;

class PullThrowListener {
public:
    explicit PullThrowListener(DragManager* manager);
    ~PullThrowListener();

    class VKObserver : public AAFwk::DataAbilityObserverStub {
    public:
        VKObserver() = default;
        ~VKObserver() = default;
        void OnChange() override;

        using UpdateFunc = std::function<void()>;
        void SetUpdateFunc(const UpdateFunc &func);
    private:
        UpdateFunc update_ = nullptr;
    };
    
    class FoldStatusListener : public Rosen::DisplayManager::IFoldStatusListener {
    public:
        explicit FoldStatusListener(PullThrowListener* listener) : listener_(listener) {}
        ~FoldStatusListener() override = default;
        DISALLOW_COPY_AND_MOVE(FoldStatusListener);
        // std::shared_ptr<MMI::PointerEvent> pointerEvent;
        /**
        * @param FoldStatus uint32_t; UNKNOWN = 0, EXPAND = 1, FOLDED = 2, HALF_FOLD = 3;
        */
        void OnFoldStatusChanged(Rosen::FoldStatus foldStatus) override;
    private:
        PullThrowListener* listener_;
    };

    class ScreenMagneticStateListener : public Rosen::DisplayManager::IScreenMagneticStateListener {
    public:
        explicit ScreenMagneticStateListener(PullThrowListener* listener) : listener_(listener) {}
        virtual ~ScreenMagneticStateListener() override = default;

        /**
        * @brief Notify listeners when screen magnetic state changed.
        *
        * @param screenMagneticState ScreenMagneticState.
        */
        void OnScreenMagneticStateChanged(bool isMagneticState) override;

    private:
        PullThrowListener* listener_;
    };

    sptr<IRemoteObject> remoteObj_ { nullptr };
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    
    int32_t GetStringValue(const std::string &key, std::string &value);
    int32_t GetIntValue(const std::string &key, int32_t &value);
    int32_t GetLongValue(const std::string &key, int64_t &value);
    
    bool ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper);
    bool ValidateThrowConditions();
    bool RegisterFoldStatusListener();
    bool RegisterScreenMagneticStateListener();
    bool RegisterVKObserver(const sptr<VKObserver> &observer);
    bool RegisterPullThrowListener();

    Rosen::FoldStatus oldFoldStatus_;
    bool currentMagneticState_ { false };
    int32_t obstatusVk_ = -1;;
    sptr<VKObserver> CreateVKObserver(const VKObserver::UpdateFunc &func);

private:
    DragManager* manager_;
    sptr<Rosen::DisplayManager::IFoldStatusListener> foldStatusListener_;
    sptr<Rosen::DisplayManager::IScreenMagneticStateListener> screenMagneticStateListener_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

#endif // PULL_THROW_LISTENER_H
