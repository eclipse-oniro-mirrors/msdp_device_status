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

#ifndef UTILITY_H
#define UTILITY_H

#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <type_traits>

namespace OHOS {
class Parcel;
namespace Msdp {
namespace DeviceStatus {

template<typename, typename = std::void_t<>>
struct IsStreamable : public std::false_type {};

template<typename T>
struct IsStreamable<T, std::void_t<decltype(operator<<(std::declval<std::ostream>(), std::declval<T>()))>>
    : public std::true_type {};

class Utility {
public:
    static size_t CopyNulstr(char *dest, size_t size, const char *src);
    static bool StartWith(const char *str, const char *prefix);
    static bool StartWith(const std::string &str, const std::string &prefix);

    static void RemoveTrailingChars(char c, char *path);
    static void RemoveTrailingChars(const std::string &toRemoved, std::string &path);
    static bool IsEmpty(const char *str) noexcept;
    static bool IsEqual(const char *s1, const char *s2) noexcept;

    template <typename... Args,
              typename = std::enable_if_t<(IsStreamable<Args>::value && ...), std::string>>
    static std::string ConcatAsString(Args&&... args)
    {
        std::ostringstream ss;
        (..., (ss << std::forward<Args>(args)));
        return ss.str();
    }

    static void RemoveSpace(std::string &str);
    static bool IsInteger(const std::string &target);

    static std::string Anonymize(const std::string &id);
    static std::string Anonymize(const char *id);
    static std::string DFXRadarAnonymize(const char* id);

    static bool DoesFileExist(const char *path);
    static ssize_t GetFileSize(const char *path);
    static ssize_t GetFileSize(const std::string &filePath);

    static void ShowFileAttributes(const char *path);
    static void ShowUserAndGroup();

    static int64_t GetSysClockTime();
};

inline bool Utility::IsEmpty(const char *str) noexcept
{
    return ((str == nullptr) || (str[0] == '\0'));
}

inline bool Utility::IsEqual(const char *s1, const char *s2) noexcept
{
    if (IsEmpty(s1)) {
        return IsEmpty(s2);
    } else if (IsEmpty(s2)) {
        return false;
    }
    return (std::strcmp(s1, s2) == 0);
}

inline std::string Utility::Anonymize(const std::string &id)
{
    return Anonymize(id.c_str());
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // UTILITY_H