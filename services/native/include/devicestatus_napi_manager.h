#include <string>
#include "pixel_map.h"

#ifndef BOOMERANG_NAPI_H
#define BOOMERANG_NAPI_H

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

typedef void (*EncodeImageFunc)(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content,
                                std::shared_ptr<Media::PixelMap> &resultPixelMap);
typedef void (*DecodeImageFunc)(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content);

class BoomerangAlgoManager {
public:
    BoomerangAlgoManager() {};
    ~BoomerangAlgoManager();
    static bool EncodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content,
                            std::shared_ptr<Media::PixelMap> &resultPixelMap);
    static bool DecodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content);
private:
    static void *boomerangAlgoHandle_;
    static EncodeImageFunc boomerangAlgoEncodeImageHandle_;
    static DecodeImageFunc boomerangAlgoDecodeImageHandle_;
};

class BoomerangAlgoImpl {
public:
    static void EncodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content,
                            std::shared_ptr<Media::PixelMap> &resultPixelMap);
    static void DecodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content);
};

}
}
}

#endif // BOOMERANG_NAPI_H