/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include <functional>
#include <map>
#include <string>

#include "devicestatus_proto.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
template<typename K, typename V>
class MsgHandler {
public:
    struct MsgCallback {
        K id;
        V fun;
    };

public:
    void Clear()
    {
        callbacks_.clear();
    }
    bool CheckKey(K id)
    {
        return (GetMsgCallback(id) != nullptr);
    }

    std::string GetDebugInfo() const
    {
        std::string str;
        for (auto &iter : callbacks_) {
            str += std::to_string(iter.first);
            str += ',';
        }
        if (str.size() > 0) {
            str.resize(str.size() - 1);
        }
        return str;
    }

    bool RegisterEvent(MsgCallback& msg)
    {
        auto it = callbacks_.find(msg.id);
        if (it != callbacks_.end()) {
            return false;
        }
        callbacks_[msg.id] = msg.fun;
        return true;
    }

protected:
    virtual ~MsgHandler() = default;
    V *GetMsgCallback(K id)
    {
        auto iter = callbacks_.find(id);
        if (iter == callbacks_.end()) {
            return nullptr;
        }
        return &iter->second;
    }

protected:
    std::map<K, V> callbacks_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // MSG_HANDLER_H
